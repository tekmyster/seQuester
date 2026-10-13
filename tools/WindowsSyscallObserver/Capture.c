// Research module, not deployed. No executable/target hashing occurs here.
#include "Capture.h"
#include "Device.h"
// Generated in an immutable build from the existing sensor CaptureToken body.
#include "SharedCaptureToken.inc"

static EX_PUSH_LOCK ScopeLock;
static PETHREAD ArmedThread;
static PEPROCESS ArmedProcess;
static HANDLE TargetHandles[SQ_SYSCALL_TARGETS];
static PFILE_OBJECT TargetObjects[SQ_SYSCALL_TARGETS];
static ULONG TargetCount;
static LONG ActiveCall;
static KSPIN_LOCK QueueLock;
static SQ_SYSCALL_RECORD Records[SQ_SYSCALL_CAPACITY];
static PFILE_OBJECT RecordTargets[SQ_SYSCALL_CAPACITY];
static GUID SourceInstance;
static NTSTATUS SourceInstanceStatus;
static ULONG Head, Count;
static volatile LONG64 Sequence, Lost, Observed;

static VOID LockScope(BOOLEAN exclusive)
{
    KeEnterCriticalRegion();
    if(exclusive)ExAcquirePushLockExclusive(&ScopeLock);
    else ExAcquirePushLockShared(&ScopeLock);
}
static VOID UnlockScope(BOOLEAN exclusive)
{
    if(exclusive)ExReleasePushLockExclusive(&ScopeLock);
    else ExReleasePushLockShared(&ScopeLock);
    KeLeaveCriticalRegion();
}
VOID SqSyscallInitialize(VOID)
{
    ExInitializePushLock(&ScopeLock);KeInitializeSpinLock(&QueueLock);
    SourceInstanceStatus=ExUuidCreate(&SourceInstance);
}
BOOLEAN SqSyscallIsArmedCurrentThread(VOID)
{
    return (PETHREAD)InterlockedCompareExchangePointer((PVOID volatile*)&ArmedThread,NULL,NULL)
        ==PsGetCurrentThread();
}
NTSTATUS SqSyscallArmCurrentThread(const HANDLE* handles, ULONG count)
{
    ULONG i;NTSTATUS status=STATUS_SUCCESS;
    PFILE_OBJECT objects[SQ_SYSCALL_TARGETS]={0};
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL||!handles||count==0||count>SQ_SYSCALL_TARGETS)
        return STATUS_INVALID_PARAMETER;
    // Handles have already been copied from the IOCTL SystemBuffer. Resolve
    // with UserMode/zero desired access, retaining the actual file objects.
    for(i=0;i<count;i++){
        status=ObReferenceObjectByHandle(handles[i],0,*IoFileObjectType,
            UserMode,(PVOID*)&objects[i],NULL);
        if(!NT_SUCCESS(status))break;
    }
    if(!NT_SUCCESS(status)){
        for(i=0;i<count;i++)if(objects[i])ObDereferenceObject(objects[i]);
        return status;
    }
    LockScope(TRUE);
    if(ArmedThread)status=STATUS_DEVICE_BUSY;
    else{
        PETHREAD thread=PsGetCurrentThread();
        ArmedProcess=PsGetCurrentProcess();
        ObReferenceObject(thread);ObReferenceObject(ArmedProcess);
        TargetCount=count;
        for(i=0;i<count;i++){
            TargetHandles[i]=handles[i];TargetObjects[i]=objects[i];objects[i]=NULL;
        }
        InterlockedExchangePointer((PVOID volatile*)&ArmedThread,thread);
    }
    UnlockScope(TRUE);
    for(i=0;i<count;i++)if(objects[i])ObDereferenceObject(objects[i]);
    return status;
}
NTSTATUS SqSyscallDisarmCurrentThread(VOID)
{
    ULONG i;NTSTATUS status=STATUS_SUCCESS;
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
    LockScope(TRUE);
    if(ArmedThread!=PsGetCurrentThread())status=STATUS_ACCESS_DENIED;
    else if(ActiveCall)status=STATUS_DEVICE_BUSY;
    else{
        PETHREAD thread=(PETHREAD)InterlockedExchangePointer((PVOID volatile*)&ArmedThread,NULL);
        for(i=0;i<TargetCount;i++){
            ObDereferenceObject(TargetObjects[i]);TargetObjects[i]=NULL;TargetHandles[i]=NULL;
        }
        TargetCount=0;
        ObDereferenceObject(ArmedProcess);ArmedProcess=NULL;
        ObDereferenceObject(thread);
    }
    UnlockScope(TRUE);return status;
}
BOOLEAN SqSyscallEnter(HANDLE handle, ULONG operation, ULONG length,
    ULONG informationClass, SQ_SYSCALL_CALL* call)
{
    ULONG i;BOOLEAN matched=FALSE,copyOnOpen=FALSE,effectiveOnly=FALSE;
    SECURITY_IMPERSONATION_LEVEL level=SecurityAnonymous;
    PACCESS_TOKEN owner=NULL,effective=NULL;
    PFILE_OBJECT current=NULL,target=NULL;NTSTATUS fileStatus;
    LARGE_INTEGER utc;
    call->Observed=FALSE;
    // Reject unrelated calls before taking a lock or clearing a large record.
    // Recheck under ScopeLock before using any retained object or target.
    if((PETHREAD)InterlockedCompareExchangePointer((PVOID volatile*)&ArmedThread,NULL,NULL)
        !=PsGetCurrentThread())return FALSE;
    // No token/object query at unsupported IRQL. Backend admission must make
    // these exclusions visible; this private owned-thread proof is PASSIVE only.
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return FALSE;
    LockScope(FALSE);
    if(ArmedThread==PsGetCurrentThread()&&ArmedProcess==PsGetCurrentProcess()){
        for(i=0;i<TargetCount;i++)if(TargetHandles[i]==handle){matched=TRUE;break;}
        if(matched&&InterlockedCompareExchange(&ActiveCall,1,0)!=0)matched=FALSE;
        if(matched){
            fileStatus=ObReferenceObjectByHandle(handle,0,*IoFileObjectType,
                UserMode,(PVOID*)&current,NULL);
            // Validate actual object on every invocation: a recycled numeric
            // handle must never inherit a previous target's identity.
            if(!NT_SUCCESS(fileStatus)||current!=TargetObjects[i])matched=FALSE;
            if(matched){target=current;ObReferenceObject(target);}
            if(current)ObDereferenceObject(current);
            if(!matched)InterlockedExchange(&ActiveCall,0);
        }
    }
    UnlockScope(FALSE);
    if(!matched)return FALSE;
    RtlZeroMemory(call,sizeof(*call));
    call->Target=target;
    call->Observed=TRUE;
    call->Record.Version=SQ_SYSCALL_SCHEMA;call->Record.Size=sizeof(call->Record);
    call->Record.Sequence=(ULONGLONG)InterlockedIncrement64(&Sequence);
    KeQuerySystemTime(&utc);call->Record.EntryUtc=(ULONGLONG)utc.QuadPart;
    call->Record.EntryMonotonic=KeQueryPerformanceCounter(NULL).QuadPart;
    call->Record.ProcessId=(ULONGLONG)PsGetCurrentProcessId();
    call->Record.ThreadId=(ULONGLONG)PsGetCurrentThreadId();
    call->Record.ProcessBirth=PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
    call->Record.TargetHandle=(ULONGLONG)handle;
    call->Record.Operation=operation;call->Record.RequestedLength=length;
    call->Record.InformationClass=informationClass;
    call->Record.CaptureIrql=KeGetCurrentIrql();
    call->Record.RequestorMode=ExGetPreviousMode();
    call->Record.FileObjectStatus=STATUS_SUCCESS;
    owner=PsReferencePrimaryToken(PsGetCurrentProcess());
    CaptureToken(owner,&call->Record.Owner);
    effective=PsReferenceImpersonationToken(PsGetCurrentThread(),&copyOnOpen,&effectiveOnly,&level);
    if(effective){
        call->Record.ImpersonationState=2;
        CaptureToken(effective,&call->Record.Effective);
        call->Record.Effective.ImpersonationLevel=level;
        PsDereferenceImpersonationToken(effective);
    }else{
        call->Record.ImpersonationState=1;
        RtlCopyMemory(&call->Record.Effective,&call->Record.Owner,sizeof(SQ_TOKEN));
    }
    PsDereferencePrimaryToken(owner);
    call->Record.AttributionStatus=(call->Record.Owner.Captured==31&&
        call->Record.Effective.Captured==31)?STATUS_SUCCESS:STATUS_PARTIAL_COPY;
    return TRUE;
}
VOID SqSyscallReturn(SQ_SYSCALL_CALL* call, NTSTATUS result)
{
    KIRQL old;LARGE_INTEGER utc;PFILE_OBJECT release=NULL;
    if(!call->Observed)return;
    call->Record.ReturnStatus=result;
    KeQuerySystemTime(&utc);call->Record.ReturnUtc=(ULONGLONG)utc.QuadPart;
    call->Record.ReturnMonotonic=KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireSpinLock(&QueueLock,&old);
    if(Count==SQ_SYSCALL_CAPACITY){InterlockedIncrement64(&Lost);release=call->Target;}
    else{ULONG slot=(Head+Count)%SQ_SYSCALL_CAPACITY;Records[slot]=call->Record;RecordTargets[slot]=call->Target;Count++;}
    call->Target=NULL;
    KeReleaseSpinLock(&QueueLock,old);
    if(release)ObDereferenceObject(release);
    InterlockedIncrement64(&Observed);call->Observed=FALSE;
    InterlockedExchange(&ActiveCall,0);
}
NTSTATUS SqSyscallReadRecord(SQ_SYSCALL_RECORD* record)
{
    KIRQL old;NTSTATUS status=STATUS_NO_MORE_ENTRIES;PFILE_OBJECT release=NULL;
    KeAcquireSpinLock(&QueueLock,&old);
    if(Count){*record=Records[Head];release=RecordTargets[Head];RecordTargets[Head]=NULL;Head=(Head+1)%SQ_SYSCALL_CAPACITY;Count--;status=STATUS_SUCCESS;}
    KeReleaseSpinLock(&QueueLock,old);if(release)ObDereferenceObject(release);return status;
}
NTSTATUS SqSyscallIntake(ULONG code,PVOID buffer,ULONG inputBytes,ULONG outputBytes,PULONG returned)
{
    SQ_INTAKE_KEY key;KIRQL old;PFILE_OBJECT target=NULL;NTSTATUS status=STATUS_NO_MORE_ENTRIES;
    C_ASSERT(sizeof(SQ_SOURCE_INFO)==56);C_ASSERT(sizeof(SQ_INTAKE_KEY)==32);C_ASSERT(sizeof(SQ_TARGET_REPLY)==3120);
    *returned=0;
    if(SourceInstanceStatus!=STATUS_SUCCESS&&SourceInstanceStatus!=RPC_NT_UUID_LOCAL_ONLY)return STATUS_DEVICE_NOT_READY;
    if(code==SQ_SOURCE){
        SQ_SOURCE_INFO* info=(SQ_SOURCE_INFO*)buffer;
        if(inputBytes||!buffer||outputBytes<sizeof(*info))return STATUS_INVALID_PARAMETER;
        RtlZeroMemory(info,sizeof(*info));info->Version=1;info->Size=sizeof(*info);info->Instance=SourceInstance;info->InstanceStatus=SourceInstanceStatus;
        SqSyscallHealth(&info->Observed,&info->Lost,&info->Queued);*returned=sizeof(*info);return STATUS_SUCCESS;
    }
    if(code==SQ_PEEK){
        if(inputBytes||!buffer||outputBytes<sizeof(SQ_SYSCALL_RECORD))return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&QueueLock,&old);
        if(Count){RtlCopyMemory(buffer,&Records[Head],sizeof(SQ_SYSCALL_RECORD));*returned=sizeof(SQ_SYSCALL_RECORD);status=STATUS_SUCCESS;}
        KeReleaseSpinLock(&QueueLock,old);return status;
    }
    if(!buffer||inputBytes!=sizeof(key))return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&key,buffer,sizeof(key));
    if(key.Version!=1||key.Size!=sizeof(key)||!key.Sequence||!RtlEqualMemory(&key.Instance,&SourceInstance,sizeof(GUID)))return STATUS_INVALID_PARAMETER;
    if(code==SQ_TARGET&&outputBytes<sizeof(SQ_TARGET_REPLY))return STATUS_BUFFER_TOO_SMALL;
    if(code==SQ_ACK&&outputBytes)return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&QueueLock,&old);
    if(Count&&Records[Head].Sequence==key.Sequence){
        target=RecordTargets[Head];
        if(code==SQ_ACK){RecordTargets[Head]=NULL;Head=(Head+1)%SQ_SYSCALL_CAPACITY;Count--;status=STATUS_SUCCESS;}
        else if(code==SQ_TARGET){if(target)ObReferenceObject(target);status=STATUS_SUCCESS;}
    }
    KeReleaseSpinLock(&QueueLock,old);
    if(!NT_SUCCESS(status))return status;
    if(code==SQ_ACK){if(target)ObDereferenceObject(target);return STATUS_SUCCESS;}
    if(code==SQ_TARGET){
        SQ_TARGET_REPLY* reply=(SQ_TARGET_REPLY*)buffer;
        POBJECT_NAME_INFORMATION name=NULL;ULONG bytes=0;LARGE_INTEGER now;
        RtlZeroMemory(reply,sizeof(*reply));reply->Version=1;reply->Size=sizeof(*reply);reply->Instance=SourceInstance;reply->Sequence=key.Sequence;
        KeQuerySystemTime(&now);reply->QueriedUtc=now.QuadPart;reply->NameStatus=STATUS_NOT_FOUND;
        if(target){
#pragma warning(suppress:4996)
            name=ExAllocatePoolWithTag(PagedPool,4096,'nSqS');
            if(!name)reply->NameStatus=STATUS_INSUFFICIENT_RESOURCES;
            else{
                reply->NameStatus=ObQueryNameString(target,name,4096,&bytes);
                if(NT_SUCCESS(reply->NameStatus)){
                    if(!name->Name.Buffer||!name->Name.Length)reply->NameStatus=STATUS_OBJECT_NAME_NOT_FOUND;
                    else if(name->Name.Length>=sizeof(reply->Name)||name->Name.Length%sizeof(WCHAR))reply->NameStatus=STATUS_NAME_TOO_LONG;
                    else{reply->NameBytes=name->Name.Length;RtlCopyMemory(reply->Name,name->Name.Buffer,name->Name.Length);}
                }
                ExFreePoolWithTag(name,'nSqS');
            }
            ObDereferenceObject(target);
        }
        *returned=sizeof(*reply);return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}
VOID SqSyscallHealth(ULONGLONG* observed, ULONGLONG* lost, ULONG* queued)
{
    KIRQL old;KeAcquireSpinLock(&QueueLock,&old);
    *observed=(ULONGLONG)InterlockedCompareExchange64(&Observed,0,0);
    *lost=(ULONGLONG)InterlockedCompareExchange64(&Lost,0,0);*queued=Count;
    KeReleaseSpinLock(&QueueLock,old);
}
