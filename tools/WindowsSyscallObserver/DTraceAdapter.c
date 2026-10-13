// Private context qualification only. Does NOT query tokens in an unqualified
// trace callback, alter interrupts/IRQL, patch Microsoft code, or emit ordinary
// syscall evidence. Keep loaded until normal reboot even after attach failure.
#include "Capture.h"
#include "DTraceAdapter.h"
#include "Bridge.h"
#include <intrin.h>
#include <ntimage.h>
#include "ntdtrace.h"

typedef NTSTATUS (NTAPI *REGISTER_ENGINE)(PCTRACE_ENGINE,PCTRACE_ENGINE_HELPERS*);
static REGISTER_ENGINE RegisterEngine;
static PFILE_OBJECT FrameworkFile;
static const TRACE_ENGINE* Original;
static TRACE_ENGINE Adapter;
static TRACE_PROVIDER_CALLBACKS SyscallCallbacks;
static NTTRACE_PROVIDER_ID SyscallProvider;
static PVOID SyscallProviderContext;
typedef struct _PROBE_BINDING {volatile LONG Id;ULONG Operation,Stage;} PROBE_BINDING;
static PROBE_BINDING Probes[6];
static KSPIN_LOCK QueueLock;
static SQ_DTRACE_CONTEXT_RECORD Records[SQ_SYSCALL_CAPACITY];
static ULONG Head,Count;
static volatile LONG64 Sequence,Observed,Lost;
static LONG AdmissionStatus=STATUS_DEVICE_NOT_READY,UnregisterStatus=STATUS_DEVICE_NOT_READY;
static LONG RegisterStatus=STATUS_DEVICE_NOT_READY,RestoreStatus=STATUS_DEVICE_NOT_READY;
static BOOLEAN Attached;
static volatile LONG64 RegisterCalls,LookupCalls,CreateCalls,FireCalls,ArmedFireCalls;
static NTTRACE_PROVIDER_ID CandidateSyscallProvider;
static volatile LONG CallbackBytes,LastArmedProbeId,LastArmedIrql,MatchedLookupCalls;

// The two backends have separate binaries. This context adapter has no VMX
// bridges and must not report its probe callbacks as EPT bridge activity.
LONG64 SqActiveBridges(VOID){return 0;}
static VOID Bind(NTTRACE_PROVIDER_ID provider,PCSZ function,PCSZ name,NTTRACE_PROBE_ID id)
{
    ULONG operation=0,stage=0,index;
    if(provider!=SyscallProvider||!function||!name||!id)return;
    if(strcmp(function,"NtReadFile")==0)operation=1;
    else if(strcmp(function,"NtWriteFile")==0)operation=2;
    else if(strcmp(function,"NtSetInformationFile")==0)operation=3;
    if(strcmp(name,"entry")==0)stage=1;else if(strcmp(name,"return")==0)stage=2;
    if(!operation||!stage)return;
    index=(operation-1)*2+stage-1;
    Probes[index].Operation=operation;Probes[index].Stage=stage;
    InterlockedExchange(&Probes[index].Id,(LONG)id);
}
static NTTRACE_PROVIDER_ID ProviderRegister(PCSZ name,PVOID context,
    PCTRACE_PROVIDER_CALLBACKS callbacks,TRACE_PROVIDER_ACCESS access)
{
    NTTRACE_PROVIDER_ID id=Original->ProviderRegister(name,context,callbacks,access);
    InterlockedIncrement64(&RegisterCalls);
    if(id&&name&&strcmp(name,"syscall")==0){
        CandidateSyscallProvider=id;
        InterlockedExchange(&CallbackBytes,callbacks?(LONG)callbacks->Size:0);
    }
    if(id&&name&&strcmp(name,"syscall")==0&&callbacks&&callbacks->Size>=sizeof(*callbacks)){
        SyscallCallbacks=*callbacks;SyscallProviderContext=context;SyscallProvider=id;
    }
    return id;
}
static NTTRACE_PROBE_ID ProbeCreate(NTTRACE_PROVIDER_ID provider,PCSZ module,
    PCSZ function,PCSZ name,INT frames,PVOID context)
{
    NTTRACE_PROBE_ID id=Original->ProbeCreate(provider,module,function,name,frames,context);
    InterlockedIncrement64(&CreateCalls);
    Bind(provider,function,name,id);return id;
}
static NTTRACE_PROBE_ID ProbeLookup(NTTRACE_PROVIDER_ID provider,PCSZ module,
    PCSZ function,PCSZ name)
{
    NTTRACE_PROBE_ID id=Original->ProbeLookup(provider,module,function,name);
    InterlockedIncrement64(&LookupCalls);
    if(function&&(strcmp(function,"NtReadFile")==0||strcmp(function,"NtWriteFile")==0||strcmp(function,"NtSetInformationFile")==0))InterlockedIncrement(&MatchedLookupCalls);
    Bind(provider,function,name,id);return id;
}
static VOID ProbeFire(NTTRACE_PROBE_ID id,UINT_PTR a0,UINT_PTR a1,
    UINT_PTR a2,UINT_PTR a3,PVOID context)
{
    ULONG i;KIRQL old;LARGE_INTEGER utc;SQ_DTRACE_CONTEXT_RECORD record;
    // Original requestor pointer identity; no PID lookup and no blocking scope
    // lock in an unknown probe context. No provider GetArgument is called yet.
    InterlockedIncrement64(&FireCalls);
    if(SqSyscallIsArmedCurrentThread()){
        InterlockedIncrement64(&ArmedFireCalls);InterlockedExchange(&LastArmedProbeId,(LONG)id);
        InterlockedExchange(&LastArmedIrql,(LONG)KeGetCurrentIrql());
        for(i=0;i<RTL_NUMBER_OF(Probes);i++)if((ULONG)InterlockedCompareExchange(&Probes[i].Id,0,0)==id&&id){
            if(KeGetCurrentIrql()>APC_LEVEL){InterlockedIncrement64(&Lost);InterlockedIncrement64(&Observed);break;}
            RtlZeroMemory(&record,sizeof(record));record.Version=1;record.Size=sizeof(record);
            record.Sequence=(ULONGLONG)InterlockedIncrement64(&Sequence);
            record.Monotonic=KeQueryPerformanceCounter(NULL).QuadPart;
            KeQuerySystemTime(&utc);record.Utc=(ULONGLONG)utc.QuadPart;
            record.ProcessId=(ULONGLONG)PsGetCurrentProcessId();record.ThreadId=(ULONGLONG)PsGetCurrentThreadId();
            record.ProcessBirth=PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
            record.ProbeId=id;record.Operation=Probes[i].Operation;record.Stage=Probes[i].Stage;
            record.Irql=KeGetCurrentIrql();record.InterruptsEnabled=(__readeflags()&0x200)!=0;
            record.AllApcsDisabled=KeAreAllApcsDisabled();
            record.Arguments[0]=a0;record.Arguments[1]=a1;record.Arguments[2]=a2;record.Arguments[3]=a3;
            // Never acquire a spin lock at IRQL above DISPATCH_LEVEL. That
            // unsupported context is counted as a loss, not a normal record.
            if(record.Irql<=DISPATCH_LEVEL){
                KeAcquireSpinLock(&QueueLock,&old);
                if(Count==SQ_SYSCALL_CAPACITY)InterlockedIncrement64(&Lost);
                else{Records[(Head+Count)%SQ_SYSCALL_CAPACITY]=record;Count++;}
                KeReleaseSpinLock(&QueueLock,old);
            }else InterlockedIncrement64(&Lost);
            InterlockedIncrement64(&Observed);break;
        }
    }
    Original->ProbeFire(id,a0,a1,a2,a3,context);
}
static NTSTATUS Admit(VOID)
{
    UNICODE_STRING name;PDEVICE_OBJECT device=NULL;NTSTATUS status;
    PUCHAR image;PIMAGE_NT_HEADERS nt;PIMAGE_DOS_HEADER dos;ULONG i;
    static const ULONG expected[]={133488,133920,132336,46576,47504,48352,47872,72688,38816};
    if(FrameworkFile)return STATUS_SUCCESS;
    RtlInitUnicodeString(&name,L"\\Device\\DTrace\\provider");
    status=IoGetDeviceObjectPointer(&name,FILE_READ_DATA,&FrameworkFile,&device);
    if(!NT_SUCCESS(status))return status;
    image=(PUCHAR)device->DriverObject->DriverStart;
    if(!image||device->DriverObject->DriverSize!=204800){status=STATUS_REVISION_MISMATCH;goto failed;}
    dos=(PIMAGE_DOS_HEADER)image;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0||
        (ULONG)dos->e_lfanew>204800-sizeof(IMAGE_NT_HEADERS)){status=STATUS_INVALID_IMAGE_FORMAT;goto failed;}
    nt=(PIMAGE_NT_HEADERS)(image+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt->OptionalHeader.SizeOfImage!=204800||
        nt->FileHeader.TimeDateStamp!=0x8C63FBDA||nt->OptionalHeader.CheckSum!=0x390FB){status=STATUS_REVISION_MISMATCH;goto failed;}
    C_ASSERT(sizeof(TRACE_ENGINE)==80);
    Original=(const TRACE_ENGINE*)(image+86240);
    if(Original->Size!=sizeof(*Original)){status=STATUS_REVISION_MISMATCH;goto failed;}
    for(i=0;i<RTL_NUMBER_OF(expected);i++){
        if(((const ULONG_PTR*)Original)[i+1]!=(ULONG_PTR)(image+expected[i])){
            status=STATUS_REVISION_MISMATCH;goto failed;
        }
    }
    // Actual exported implementation and verified ntdtrace.h calling contract.
    // No MmGetSystemRoutineAddress claim for non-kernel module exports.
    RegisterEngine=(REGISTER_ENGINE)(image+114704);
    Adapter=*Original;Adapter.ProviderRegister=ProviderRegister;
    Adapter.ProbeCreate=ProbeCreate;Adapter.ProbeLookup=ProbeLookup;Adapter.ProbeFire=ProbeFire;
    return STATUS_SUCCESS;
failed:
    ObDereferenceObject(FrameworkFile);FrameworkFile=NULL;Original=NULL;return status;
}
NTSTATUS SqDtraceControl(ULONG code,PVOID buffer,ULONG input,ULONG output,PULONG bytes)
{
    NTSTATUS status;KIRQL old;ULONG i;PCTRACE_ENGINE_HELPERS helpers=NULL;
    *bytes=0;if(KeGetCurrentIrql()!=PASSIVE_LEVEL||input!=0)return STATUS_INVALID_PARAMETER;
    if(code==SQ_DTRACE_ATTACH){
        if(Attached)return STATUS_DEVICE_BUSY;
        AdmissionStatus=Admit();if(!NT_SUCCESS(AdmissionStatus))return AdmissionStatus;
        UnregisterStatus=RegisterEngine(NULL,NULL);if(!NT_SUCCESS(UnregisterStatus))return UnregisterStatus;
        RtlZeroMemory(Probes,sizeof(Probes));SyscallProvider=0;
        RegisterStatus=RegisterEngine(&Adapter,&helpers);
        if(NT_SUCCESS(RegisterStatus)){Attached=TRUE;return STATUS_SUCCESS;}
        RestoreStatus=RegisterEngine(Original,&helpers);
        // The installed demand driver is retained even on failed restoration.
        // No automatic unload; failure remains visible through health.
        return RegisterStatus;
    }
    if(code==SQ_DTRACE_RESTORE){
        if(!Attached)return STATUS_INVALID_DEVICE_STATE;
        UnregisterStatus=RegisterEngine(NULL,NULL);if(!NT_SUCCESS(UnregisterStatus))return UnregisterStatus;
        RestoreStatus=RegisterEngine(Original,&helpers);if(!NT_SUCCESS(RestoreStatus))return RestoreStatus;
        Attached=FALSE;return STATUS_SUCCESS;
    }
    if(code==SQ_DTRACE_CONTEXT){
        if(output<sizeof(SQ_DTRACE_CONTEXT_RECORD))return STATUS_BUFFER_TOO_SMALL;
        status=STATUS_NO_MORE_ENTRIES;KeAcquireSpinLock(&QueueLock,&old);
        if(Count){*(SQ_DTRACE_CONTEXT_RECORD*)buffer=Records[Head];Head=(Head+1)%SQ_SYSCALL_CAPACITY;Count--;status=STATUS_SUCCESS;*bytes=sizeof(SQ_DTRACE_CONTEXT_RECORD);}
        KeReleaseSpinLock(&QueueLock,old);return status;
    }
    if(code==SQ_DTRACE_HEALTH){
        SQ_DTRACE_HEALTH_RECORD* h=(SQ_DTRACE_HEALTH_RECORD*)buffer;
        if(output<sizeof(*h))return STATUS_BUFFER_TOO_SMALL;
        RtlZeroMemory(h,sizeof(*h));h->Version=1;h->Size=sizeof(*h);h->Attached=Attached;
        KeAcquireSpinLock(&QueueLock,&old);h->Queued=Count;h->Observed=Observed;h->Lost=Lost;KeReleaseSpinLock(&QueueLock,old);
        h->AdmissionStatus=AdmissionStatus;h->UnregisterStatus=UnregisterStatus;h->RegisterStatus=RegisterStatus;h->RestoreStatus=RestoreStatus;
        for(i=0;i<RTL_NUMBER_OF(Probes);i++)if(Probes[i].Id)h->BoundProbes++;
        h->RegisterCalls=InterlockedCompareExchange64(&RegisterCalls,0,0);
        h->LookupCalls=InterlockedCompareExchange64(&LookupCalls,0,0);h->CreateCalls=InterlockedCompareExchange64(&CreateCalls,0,0);
        h->FireCalls=InterlockedCompareExchange64(&FireCalls,0,0);h->ArmedFireCalls=InterlockedCompareExchange64(&ArmedFireCalls,0,0);
        h->CandidateSyscallProvider=CandidateSyscallProvider;h->BoundSyscallProvider=SyscallProvider;
        h->CallbackBytes=(ULONG)InterlockedCompareExchange(&CallbackBytes,0,0);
        h->LastArmedProbeId=(ULONG)InterlockedCompareExchange(&LastArmedProbeId,0,0);
        h->LastArmedIrql=(ULONG)InterlockedCompareExchange(&LastArmedIrql,0,0);
        h->MatchedLookupCalls=(ULONG)InterlockedCompareExchange(&MatchedLookupCalls,0,0);
        *bytes=sizeof(*h);return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path)
{
    UNREFERENCED_PARAMETER(path);SqSyscallInitialize();KeInitializeSpinLock(&QueueLock);
    return SqInstallDevice(driver);
}
