// Private Windows 10 boot-time tracing qualification. No kernel patching,
// interrupt manipulation or production publication. Token mode is separately
// compiled and admitted only after actual callback-context qualification.
#include "Capture.h"
#include "DTraceAdapter.h"
#include "Bridge.h"
#include <intrin.h>

typedef NTSTATUS (NTAPI *SET_SERVICE_CALLBACK)(PCSZ,BOOLEAN,PVOID,PVOID);
typedef struct _BOOT_KERNEL_CONTEXT {
 ULONG Size,TracePrivateOffset,TracePrivateCount,TrapFrameOffset;
 ULONGLONG TebOffset;
 SET_SERVICE_CALLBACK SetServiceCallback;
 PVOID SetTracepoint,RegisterEventCallback,GetBaseTrapFrame,GetTrapFrameRegister,EnumerateSystemImages;
} BOOT_KERNEL_CONTEXT;
C_ASSERT(sizeof(BOOT_KERNEL_CONTEXT)==72);
static const BOOT_KERNEL_CONTEXT* KernelContext;
static volatile LONG BootInitialized,Attached,Ready;
static volatile LONG InitializerEntered;
static NTSTATUS InitializerStatus=STATUS_DEVICE_NOT_READY;
static SQ_DTRACE_CONTEXT_RECORD Records[SQ_SYSCALL_CAPACITY];
static volatile LONG64 WritePosition,ReadPosition,Sequence,Observed,Lost,RegisterCalls,FireCalls,ArmedFireCalls;
static volatile LONG LastArmedIrql,LastArmedStage;
static LONG AdmissionStatus=STATUS_DEVICE_NOT_READY,RegisterStatus=STATUS_DEVICE_NOT_READY,RestoreStatus=STATUS_DEVICE_NOT_READY;
static ULONG Bound;
static const CHAR* Names[]={"ReadFile","WriteFile","SetInformationFile"};
#ifdef SQ_BOOT_TOKEN_CAPTURE
static SQ_SYSCALL_CALL OwnedCall;
static ULONG TokenCallDepth,TokenCaptureDepth;
static BOOLEAN TokenEnriching;
static VOID EnterTokens(ULONG operation,ULONG totalArguments,ULONG registerCount,
 const ULONG_PTR* arguments,const ULONG_PTR* stackArguments)
{
 ULONG length,informationClass=0;
 // Never enable interrupts or lower IRQL to make a token query possible.
 // Context observations remain available even when this guard rejects capture.
 if(TokenEnriching||!SqSyscallIsArmedCurrentThread()||KeGetCurrentIrql()!=PASSIVE_LEVEL||
    (__readeflags()&0x200)==0||KeAreAllApcsDisabled()||
    registerCount!=4||!arguments||!stackArguments||OwnedCall.Observed)return;
 TokenEnriching=TRUE;
 __try{
  __try{
   if(operation==SQ_SYSCALL_READ||operation==SQ_SYSCALL_WRITE){
    if(totalArguments!=9)return;
    length=(ULONG)stackArguments[2];
   }else if(operation==SQ_SYSCALL_SET_INFORMATION){
    if(totalArguments!=5)return;
    length=(ULONG)arguments[3];informationClass=(ULONG)stackArguments[0];
   }else return;
  }__except(EXCEPTION_EXECUTE_HANDLER){return;}
  TokenCaptureDepth=TokenCallDepth;
  if(!SqSyscallEnter((HANDLE)arguments[0],operation,length,informationClass,&OwnedCall))TokenCaptureDepth=0;
 }__finally{TokenEnriching=FALSE;}
}
#endif
LONG64 SqActiveBridges(VOID){return 0;}

static VOID Observe(ULONG operation,ULONG stage,ULONG count,const ULONG_PTR* arguments)
{
 SQ_DTRACE_CONTEXT_RECORD record;LARGE_INTEGER utc;LONG64 w,r;ULONG i;
 InterlockedIncrement64(&FireCalls);
 if(!InterlockedCompareExchange(&Ready,0,0)||!SqSyscallIsArmedCurrentThread())return;
 InterlockedIncrement64(&ArmedFireCalls);InterlockedExchange(&LastArmedIrql,(LONG)KeGetCurrentIrql());
 InterlockedExchange(&LastArmedStage,(LONG)stage);
 // Context-only SPSC queue: one retained owned thread produces and consumes.
 // No spin lock, IRQL change, interrupt enablement or paged API is required.
 w=InterlockedCompareExchange64(&WritePosition,0,0);r=InterlockedCompareExchange64(&ReadPosition,0,0);
 if(w-r>=SQ_SYSCALL_CAPACITY){InterlockedIncrement64(&Lost);return;}
 RtlZeroMemory(&record,sizeof(record));record.Version=1;record.Size=sizeof(record);
 record.Sequence=(ULONGLONG)InterlockedIncrement64(&Sequence);
 record.Monotonic=KeQueryPerformanceCounter(NULL).QuadPart;KeQuerySystemTime(&utc);record.Utc=(ULONGLONG)utc.QuadPart;
 record.ProcessId=(ULONGLONG)PsGetCurrentProcessId();record.ThreadId=(ULONGLONG)PsGetCurrentThreadId();
 record.ProcessBirth=PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
 record.ProbeId=(operation-1)*2+stage;record.Operation=operation;record.Stage=stage;
 record.Irql=KeGetCurrentIrql();record.InterruptsEnabled=(__readeflags()&0x200)!=0;record.AllApcsDisabled=KeAreAllApcsDisabled();
 if(arguments){for(i=0;i<4&&i<count;i++)record.Arguments[i]=(ULONGLONG)arguments[i];}
 Records[w%SQ_SYSCALL_CAPACITY]=record;
 InterlockedExchange64(&WritePosition,w+1);InterlockedIncrement64(&Observed);
}
static VOID NTAPI Entry(PVOID routine,PVOID context,ULONG totalArguments,const ULONG_PTR* registerArguments,
 ULONG registerCount,const ULONG_PTR* stackArguments)
{
 ULONG operation=(ULONG)(ULONG_PTR)context;
#ifdef SQ_BOOT_TOKEN_CAPTURE
 BOOLEAN scoped=SqSyscallIsArmedCurrentThread();
 if(scoped)TokenCallDepth++;
#endif
 UNREFERENCED_PARAMETER(routine);UNREFERENCED_PARAMETER(totalArguments);UNREFERENCED_PARAMETER(stackArguments);
 if(operation>=1&&operation<=3)Observe(operation,1,registerCount,registerArguments);
#ifdef SQ_BOOT_TOKEN_CAPTURE
 if(scoped&&operation>=1&&operation<=3&&InterlockedCompareExchange(&Ready,0,0))
  EnterTokens(operation,totalArguments,registerCount,registerArguments,stackArguments);
#endif
}
static VOID NTAPI Returned(PVOID routine,PVOID context,ULONG totalArguments,const ULONG_PTR* arguments,
 ULONG registerCount,const ULONG_PTR* stackArguments)
{
 ULONG operation=(ULONG)(ULONG_PTR)context;
 UNREFERENCED_PARAMETER(routine);UNREFERENCED_PARAMETER(totalArguments);UNREFERENCED_PARAMETER(stackArguments);
 if(operation>=1&&operation<=3)Observe(operation,2,registerCount,arguments);
#ifdef SQ_BOOT_TOKEN_CAPTURE
 if(SqSyscallIsArmedCurrentThread()){
  // Enrichment can invoke a nested monitored syscall. Its return must not
  // complete the outer operation's token record, even when the opcode matches.
  if(!TokenEnriching&&OwnedCall.Observed&&TokenCallDepth==TokenCaptureDepth&&
     OwnedCall.Record.Operation==operation&&registerCount==1&&arguments&&
     KeGetCurrentIrql()==PASSIVE_LEVEL&&(__readeflags()&0x200)!=0){
   SqSyscallReturn(&OwnedCall,(NTSTATUS)arguments[0]);TokenCaptureDepth=0;
  }
  if(TokenCallDepth)TokenCallDepth--;
 }
#endif
}
static BOOLEAN NTAPI UnsupportedMemory(PVOID systemAddress,ULONG_PTR untrustedAddress,SIZE_T bytes,SIZE_T chunk,BOOLEAN read)
{
 UNREFERENCED_PARAMETER(systemAddress);UNREFERENCED_PARAMETER(untrustedAddress);UNREFERENCED_PARAMETER(bytes);
 UNREFERENCED_PARAMETER(chunk);UNREFERENCED_PARAMETER(read);return FALSE;
}
// Exact pinned Windows 10 boot protocol verified in the matching kernel PDB
// and caller disassembly. The kernel writes its context POINTER through the
// returned address; this is not a guessed context-buffer copy operation.
__declspec(dllexport) NTSTATUS NTAPI TraceInitSystem(const BOOT_KERNEL_CONTEXT*** contextAddress,
 ULONG_PTR* callouts,PVOID* memoryAccess)
{
 ULONG i;
 InterlockedExchange(&InitializerEntered,1);
 InitializerStatus=STATUS_REVISION_MISMATCH;
 if(!contextAddress||!callouts||!memoryAccess||callouts[0]!=9)return InitializerStatus;
 *contextAddress=&KernelContext;
 // Slot zero is the kernel-supplied table extent, not a callback.
 for(i=1;i<9;i++)callouts[i]=0;
 callouts[2]=(ULONG_PTR)Entry;callouts[3]=(ULONG_PTR)Returned;
 *memoryAccess=(PVOID)UnsupportedMemory;InitializerStatus=STATUS_SUCCESS;
 InterlockedExchange(&BootInitialized,1);return STATUS_SUCCESS;
}
static NTSTATUS Admit(VOID)
{
 UNICODE_STRING name;PUCHAR image;PVOID read;
 if(!InterlockedCompareExchange(&BootInitialized,0,0)||!KernelContext)
  return InterlockedCompareExchange(&InitializerEntered,0,0)&&!NT_SUCCESS(InitializerStatus)
   ?InitializerStatus:STATUS_DEVICE_NOT_READY;
 RtlInitUnicodeString(&name,L"NtReadFile");read=MmGetSystemRoutineAddress(&name);
 if(!read)return STATUS_PROCEDURE_NOT_FOUND;
 image=(PUCHAR)read-0x6C9BE0;
 // Exact actual kernel context and callback RVA; do not use an arbitrary private
 // kernel pointer on another Windows build. Full image SHA is a host preflight.
 if(KernelContext->Size!=72||KernelContext->TracePrivateOffset!=0x3C0||KernelContext->TracePrivateCount!=1||
    KernelContext->TrapFrameOffset!=0x90||KernelContext->TebOffset!=0xF0||
    (PVOID)KernelContext->SetServiceCallback!=(PVOID)(image+0x8BCD40))return STATUS_REVISION_MISMATCH;
 return STATUS_SUCCESS;
}
NTSTATUS SqDtraceControl(ULONG code,PVOID buffer,ULONG input,ULONG output,PULONG bytes)
{
 ULONG i;NTSTATUS status;LONG64 r,w;
 *bytes=0;if(KeGetCurrentIrql()!=PASSIVE_LEVEL||input!=0)return STATUS_INVALID_PARAMETER;
 if(code==SQ_DTRACE_ATTACH){
  if(InterlockedCompareExchange(&Attached,0,0))return STATUS_DEVICE_BUSY;
  AdmissionStatus=Admit();if(!NT_SUCCESS(AdmissionStatus))return AdmissionStatus;
  RegisterStatus=STATUS_SUCCESS;Bound=0;
  for(i=0;i<3;i++){
   status=KernelContext->SetServiceCallback(Names[i],TRUE,(PVOID)Entry,(PVOID)(ULONG_PTR)(i+1));InterlockedIncrement64(&RegisterCalls);
   if(!NT_SUCCESS(status)){RegisterStatus=status;break;}Bound++;
   status=KernelContext->SetServiceCallback(Names[i],FALSE,(PVOID)Returned,(PVOID)(ULONG_PTR)(i+1));InterlockedIncrement64(&RegisterCalls);
   if(!NT_SUCCESS(status)){RegisterStatus=status;break;}Bound++;
  }
  if(!NT_SUCCESS(RegisterStatus)){
   // Keep boot-mapped code resident regardless of rollback outcome.
   RestoreStatus=STATUS_SUCCESS;
   for(i=0;i<3;i++){
    status=KernelContext->SetServiceCallback(Names[i],TRUE,NULL,NULL);if(!NT_SUCCESS(status))RestoreStatus=status;
    status=KernelContext->SetServiceCallback(Names[i],FALSE,NULL,NULL);if(!NT_SUCCESS(status))RestoreStatus=status;
   }
   return RegisterStatus;
  }
  InterlockedExchange(&Attached,1);return STATUS_SUCCESS;
 }
 if(code==SQ_DTRACE_RESTORE){
  if(!InterlockedCompareExchange(&Attached,0,0))return STATUS_INVALID_DEVICE_STATE;
  RestoreStatus=STATUS_SUCCESS;
  for(i=0;i<3;i++){
   status=KernelContext->SetServiceCallback(Names[i],TRUE,NULL,NULL);if(!NT_SUCCESS(status))RestoreStatus=status;
   status=KernelContext->SetServiceCallback(Names[i],FALSE,NULL,NULL);if(!NT_SUCCESS(status))RestoreStatus=status;
  }
  if(NT_SUCCESS(RestoreStatus)){Bound=0;InterlockedExchange(&Attached,0);}return RestoreStatus;
 }
 if(code==SQ_DTRACE_CONTEXT){
  if(output<sizeof(SQ_DTRACE_CONTEXT_RECORD))return STATUS_BUFFER_TOO_SMALL;
  if(!SqSyscallIsArmedCurrentThread())return STATUS_ACCESS_DENIED;
  r=InterlockedCompareExchange64(&ReadPosition,0,0);w=InterlockedCompareExchange64(&WritePosition,0,0);
  if(r==w)return STATUS_NO_MORE_ENTRIES;
  *(SQ_DTRACE_CONTEXT_RECORD*)buffer=Records[r%SQ_SYSCALL_CAPACITY];InterlockedExchange64(&ReadPosition,r+1);
  *bytes=sizeof(SQ_DTRACE_CONTEXT_RECORD);return STATUS_SUCCESS;
 }
 if(code==SQ_DTRACE_HEALTH){
  SQ_DTRACE_HEALTH_RECORD* h=(SQ_DTRACE_HEALTH_RECORD*)buffer;
  if(output<sizeof(*h))return STATUS_BUFFER_TOO_SMALL;
  RtlZeroMemory(h,sizeof(*h));h->Version=1;h->Size=sizeof(*h);h->Attached=InterlockedCompareExchange(&Attached,0,0);
  r=InterlockedCompareExchange64(&ReadPosition,0,0);w=InterlockedCompareExchange64(&WritePosition,0,0);h->Queued=(ULONG)(w-r);
  h->Observed=InterlockedCompareExchange64(&Observed,0,0);h->Lost=InterlockedCompareExchange64(&Lost,0,0);
  h->AdmissionStatus=AdmissionStatus;h->RegisterStatus=RegisterStatus;h->RestoreStatus=RestoreStatus;h->UnregisterStatus=STATUS_NOT_SUPPORTED;h->BoundProbes=Bound;
  h->RegisterCalls=InterlockedCompareExchange64(&RegisterCalls,0,0);h->FireCalls=InterlockedCompareExchange64(&FireCalls,0,0);
  h->ArmedFireCalls=InterlockedCompareExchange64(&ArmedFireCalls,0,0);h->CallbackBytes=KernelContext?KernelContext->Size:0;
  h->LastArmedProbeId=InterlockedCompareExchange(&LastArmedStage,0,0);h->LastArmedIrql=InterlockedCompareExchange(&LastArmedIrql,0,0);
  *bytes=sizeof(*h);return STATUS_SUCCESS;
 }
 return STATUS_INVALID_DEVICE_REQUEST;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path)
{
 NTSTATUS status;UNREFERENCED_PARAMETER(path);SqSyscallInitialize();status=SqInstallDevice(driver);
 if(NT_SUCCESS(status))InterlockedExchange(&Ready,1);
 // Boot callout addresses must never be unmapped through an entry failure.
 // Device failure remains a failed qualification, recoverable by normal reboot.
 driver->DriverUnload=NULL;return STATUS_SUCCESS;
}
