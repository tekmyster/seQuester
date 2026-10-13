#pragma warning(push)
#pragma warning(disable:4324) // WDK's deliberately aligned public structures.
#define FLT_MGR_LEGACY_PUSH_LOCKS 1 // Retain the Filter Manager APIs available on older supported kernels.
#include <fltKernel.h>
#pragma warning(pop)
#include <ntstrsafe.h>
#include "Protocol.h"
#include "OperationAcquisitionOutcome.h"
#ifdef SQ_POST_CREATE_DIAGNOSTIC
#include "ExecutableAccess.h"
#endif
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
#include "ExecutableStagingDiagnostic.h"
#endif
#ifdef SQ_IMAGE_DIAGNOSTIC
#include "ImageDiagnostic.h"
#endif

#define SQ_TAG 'qSqS'
typedef struct _SQ_RECORD { LIST_ENTRY Link; SQ_EVENT Event; SQ_THREAD_CONTEXT ThreadContext;
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
    SQ_DEFERRED_TOKEN_CONTEXT Deferred;
    PACCESS_TOKEN DeferredToken;
    PEPROCESS DeferredRequestor, DeferredOwner;
#endif
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    BOOLEAN StDiagnosticOnly, StNameQualified;
    ULONG StMappedRequestedAccess, StOriginalRequestedAccess;
    SB_BINDING StBinding;
    ST_BLOB* StPinnedBlob;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    SQ_ACQUISITION_OUTCOME AcquisitionOutcome;
#endif
#endif
} SQ_RECORD;
static PFLT_FILTER Filter;
static PFLT_PORT ServerPort, ClientPort;
static EX_PUSH_LOCK PortLock;
static ULONG_PTR ConnectionSequence;
static PVOID ActiveConnectionCookie;
static EX_RUNDOWN_REF ConnectionCommands;
static KEVENT PortDetached;
static BOOLEAN PortClosing, PortShutdown;
static EX_PUSH_LOCK RootLock;
static WCHAR RootBuffer[SQ_PATH_CHARS];
static UNICODE_STRING Root;
typedef struct _SQ_PATH_SET { ULONG Count; WCHAR Paths[SQ_MAX_PATHS][SQ_PATH_CHARS]; } SQ_PATH_SET;
static SQ_PATH_SET* ExactPaths;
static KSPIN_LOCK QueueLock;
static LIST_ENTRY Queue;
static volatile LONG Queued, Allocated, RootConfigured;
static volatile LONG64 Sequence, Dropped, NameFailures;
static ULONGLONG Instance;
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
static VOID DeferredReference(PFLT_CALLBACK_DATA data,SQ_RECORD* record);
static VOID DeferredSubmit(SQ_RECORD* record);
static NTSTATUS DeferredStart(VOID);
static VOID DeferredStop(VOID);
#endif

// NonPagedPoolNx is available on Windows 8/Server 2012; ExAllocatePool2 is not.
// Zero every allocation before publication, including bytes copied to user mode.
static PVOID Allocate(BOOLEAN nonpaged,SIZE_T bytes)
{
#pragma warning(suppress:4996)
    PVOID value=ExAllocatePoolWithTag(nonpaged?NonPagedPoolNx:PagedPool,bytes,SQ_TAG);
    if(value)RtlZeroMemory(value,bytes);
    return value;
}
static VOID ReleaseRecord(SQ_RECORD* record)
{
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StReleaseOperation(record->StPinnedBlob);
#endif
    ExFreePoolWithTag(record,SQ_TAG);InterlockedDecrement(&Allocated);
}

static VOID CopyText(WCHAR* output, const UNICODE_STRING* input, ULONG* flags)
{
    USHORT length=input->Length;
    if(length>=(SQ_PATH_CHARS*sizeof(WCHAR))) { length=(SQ_PATH_CHARS-1)*sizeof(WCHAR); *flags|=SQ_F_TRUNCATED; }
    RtlCopyMemory(output,input->Buffer,length); output[length/sizeof(WCHAR)]=0;
}
static VOID CaptureToken(PACCESS_TOKEN token,SQ_TOKEN* output)
{
    PTOKEN_USER user=NULL;
    PTOKEN_STATISTICS statistics=NULL;
    PTOKEN_ELEVATION elevation=NULL;
    union {PVOID Pointer;ULONG Scalar;} integrity={0},session={0};
    output->UserStatus=output->StatisticsStatus=output->SessionStatus=output->IntegrityStatus=output->ElevationStatus=STATUS_NOT_FOUND;
    if(!token)return;
    output->UserStatus=SeQueryInformationToken(token,TokenUser,(PVOID*)&user);
    if(NT_SUCCESS(output->UserStatus)) {
        ULONG size=RtlLengthSid(user->User.Sid);
        if(size<=SQ_SID_BYTES && RtlValidSid(user->User.Sid)) { RtlCopyMemory(output->Sid,user->User.Sid,size);output->SidLength=size;output->Captured|=1; }
        else output->UserStatus=STATUS_INVALID_SID;
        ExFreePool(user);
    }
    output->StatisticsStatus=SeQueryInformationToken(token,TokenStatistics,(PVOID*)&statistics);
    if(NT_SUCCESS(output->StatisticsStatus)){
        RtlCopyMemory(&output->TokenId,&statistics->TokenId,sizeof(LUID));RtlCopyMemory(&output->AuthenticationId,&statistics->AuthenticationId,sizeof(LUID));RtlCopyMemory(&output->ModifiedId,&statistics->ModifiedId,sizeof(LUID));
        output->TokenType=statistics->TokenType;output->ImpersonationLevel=statistics->TokenType==TokenImpersonation?statistics->ImpersonationLevel:0xffffffff;output->Captured|=2;ExFreePool(statistics);
    }
    // TokenSessionId is QUERY_TYPE_ULONG in ntifs.h: this documented query
    // writes a DWORD, not an allocated pointer. SeQuerySessionIdToken is
    // reserved for system use and is not the supported sensor API.
    output->SessionStatus=SeQueryInformationToken(token,TokenSessionId,&session.Pointer);
    if(NT_SUCCESS(output->SessionStatus)){output->SessionId=session.Scalar;output->Captured|=4;}
    // WDK ntifs.h QUERY_TYPE_ULONG explicitly writes a ULONG to the output argument for this class.
    // Unlike TokenUser/Statistics this is NOT an allocated TOKEN_MANDATORY_LABEL or pool pointer.
    output->IntegrityStatus=SeQueryInformationToken(token,TokenIntegrityLevel,&integrity.Pointer);
    if(NT_SUCCESS(output->IntegrityStatus)){output->IntegrityRid=integrity.Scalar;output->Captured|=8;}
    output->ElevationStatus=SeQueryInformationToken(token,TokenElevation,(PVOID*)&elevation);
    if(NT_SUCCESS(output->ElevationStatus)){output->Elevated=elevation->TokenIsElevated;output->Captured|=16;ExFreePool(elevation);}
    // A held reference prevents token-object substitution, not mutation. Never call a
    // multi-query snapshot complete when its modification marker changed.
    statistics=NULL;
    if(output->Captured&2){
        NTSTATUS checked=SeQueryInformationToken(token,TokenStatistics,(PVOID*)&statistics);
        if(!NT_SUCCESS(checked)){output->StatisticsStatus=checked;output->Captured&=~2u;}
        else{
            if(RtlCompareMemory(&output->ModifiedId,&statistics->ModifiedId,sizeof(LUID))!=sizeof(LUID)){
                output->StatisticsStatus=STATUS_RETRY;output->Captured&=~2u;
            }
            ExFreePool(statistics);
        }
    }
}
static VOID CaptureActor(PFLT_CALLBACK_DATA data,SQ_RECORD* record)
{
    SQ_EVENT* event=&record->Event;
    PEPROCESS process=FltGetRequestorProcess(data);
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    record->StPinnedBlob=StObserveBinding(process,event->Instance,event->Sequence,&record->StBinding,
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        &record->AcquisitionOutcome
#else
        NULL
#endif
        );
#endif
    event->ProcessId=(ULONGLONG)FltGetRequestorProcessId(data);
    event->RequestorMode=data->RequestorMode;
    event->CaptureIrql=KeGetCurrentIrql();
    record->ThreadContext.Version=1;record->ThreadContext.Size=sizeof(SQ_THREAD_CONTEXT);
    record->ThreadContext.Instance=event->Instance;record->ThreadContext.Sequence=event->Sequence;
    record->ThreadContext.CallbackDataFlags=data->Flags;record->ThreadContext.RequestorMode=data->RequestorMode;
    CaptureToken(NULL,&record->ThreadContext.ThreadOwnerPrimary);
    if(data->Thread) {event->ThreadId=(ULONGLONG)PsGetThreadId(data->Thread);event->ThreadProcessId=(ULONG)(ULONG_PTR)PsGetThreadProcessId(data->Thread);}
    else event->Flags|=SQ_F_THREAD_ABSENT;
    CaptureToken(NULL,&event->CreateAuthorization);CaptureToken(NULL,&event->ThreadEffective);CaptureToken(NULL,&event->RequestorPrimary);
    if(!process)event->Flags|=SQ_F_PROCESS_ABSENT|SQ_F_IMAGE_ABSENT;
    else event->ProcessCreatedUtc=PsGetProcessCreateTimeQuadPart(process);
    // The additive diagnostic holds the actual thread token at APC entry;
    // legacy fields remain explicitly partial until a versioned consumer opts in.
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
    if(KeGetCurrentIrql()==APC_LEVEL)DeferredReference(data,record);
#endif
    // APIs below require PASSIVE_LEVEL. An unsupported context is an explicit partial event.
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL) {event->Flags|=SQ_F_CONTEXT_IRQL|SQ_F_IMAGE_ABSENT|SQ_F_SUBJECT_ABSENT;return;}
    if(process){
        PUNICODE_STRING image=NULL;
        if(NT_SUCCESS(SeLocateProcessImageName(process,&image))) {CopyText(event->Image,image,&event->Flags);if(!image->Length)event->Flags|=SQ_F_IMAGE_ABSENT;ExFreePool(image);}
        else event->Flags|=SQ_F_IMAGE_ABSENT;
        SECURITY_SUBJECT_CONTEXT subject;
        SeCaptureSubjectContextEx(NULL,process,&subject);SeLockSubjectContext(&subject);
        CaptureToken(SeQuerySubjectContextToken(&subject),&event->RequestorPrimary);
        SeUnlockSubjectContext(&subject);SeReleaseSubjectContext(&subject);
        event->PrimarySidLength=event->RequestorPrimary.SidLength;RtlCopyMemory(event->PrimarySid,event->RequestorPrimary.Sid,SQ_SID_BYTES);
    }
    if(data->Thread){
        PEPROCESS owner=IoThreadToProcess(data->Thread);
        BOOLEAN copyOnOpen,effectiveOnly;SECURITY_IMPERSONATION_LEVEL level;
        if(owner){
            PACCESS_TOKEN ownerToken=PsReferencePrimaryToken(owner);
            record->ThreadContext.ThreadProcessCreatedUtc=PsGetProcessCreateTimeQuadPart(owner);
            CaptureToken(ownerToken,&record->ThreadContext.ThreadOwnerPrimary);
            PsDereferencePrimaryToken(ownerToken);
        }
        PACCESS_TOKEN threadToken=PsReferenceImpersonationToken(data->Thread,&copyOnOpen,&effectiveOnly,&level);
        event->ThreadImpersonation=threadToken?2:1;
        if(threadToken){event->ThreadCopyOnOpen=copyOnOpen?2:1;event->ThreadEffectiveOnly=effectiveOnly?2:1;}
        if(threadToken){CaptureToken(threadToken,&event->ThreadEffective);event->ThreadEffective.ImpersonationLevel=level;PsDereferenceImpersonationToken(threadToken);event->Flags|=SQ_F_IMPERSONATING;}
        else {
            // The thread's creating process may differ from FltGetRequestorProcess
            // while attached. Its effective primary token must not be invented
            // by copying the attached process's primary token.
            RtlCopyMemory(&event->ThreadEffective,&record->ThreadContext.ThreadOwnerPrimary,sizeof(SQ_TOKEN));
        }
    }
    // CREATE authorization exists independently of Thread; never discard it merely because Thread is NULL.
    if(data->Iopb->MajorFunction==IRP_MJ_CREATE && data->Iopb->Parameters.Create.SecurityContext && data->Iopb->Parameters.Create.SecurityContext->AccessState){
        PSECURITY_SUBJECT_CONTEXT subject=&data->Iopb->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext;
        SeLockSubjectContext(subject);CaptureToken(SeQuerySubjectContextToken(subject),&event->CreateAuthorization);SeUnlockSubjectContext(subject);
        event->SubjectSource=1;event->SidLength=event->CreateAuthorization.SidLength;RtlCopyMemory(event->Sid,event->CreateAuthorization.Sid,SQ_SID_BYTES);
    }else if(data->Thread){event->SubjectSource=2;event->SidLength=event->ThreadEffective.SidLength;RtlCopyMemory(event->Sid,event->ThreadEffective.Sid,SQ_SID_BYTES);}
    if(!event->SidLength)event->Flags|=SQ_F_SUBJECT_ABSENT;
}
static BOOLEAN IsWatched(const UNICODE_STRING* name)
{
    BOOLEAN result;
    FltAcquirePushLockShared(&RootLock);
    result=Root.Length && RtlPrefixUnicodeString(&Root,name,TRUE);
    if(ExactPaths){ULONG i;for(i=0;i<ExactPaths->Count&&!result;i++){UNICODE_STRING path;RtlInitUnicodeString(&path,ExactPaths->Paths[i]);result=RtlEqualUnicodeString(&path,name,TRUE);}}
    FltReleasePushLock(&RootLock);return result;
}
static VOID Enqueue(SQ_RECORD* record)
{
    KIRQL irql;
    KeAcquireSpinLock(&QueueLock,&irql);
    InsertTailList(&Queue,&record->Link);Queued++;
    KeReleaseSpinLock(&QueueLock,irql);
}
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
#include "DeferredTokenDiagnostic.h"
#endif
#ifdef SQ_POST_CREATE_DIAGNOSTIC
static FLT_PREOP_CALLBACK_STATUS CapturePreOperation(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
#else
static FLT_PREOP_CALLBACK_STATUS PreOperation(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
#endif
{
    PFLT_FILE_NAME_INFORMATION name=NULL;
    SQ_RECORD* record;
    NTSTATUS status;
    NTSTATUS normalizedStatus;
    ULONG nameSource=1;
    UNREFERENCED_PARAMETER(objects);
    *context=NULL;
    if(!InterlockedCompareExchange(&RootConfigured,0,0))return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if(KeGetCurrentIrql()>APC_LEVEL){InterlockedIncrement64(&NameFailures);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    status=FltGetFileNameInformation(data,FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT,&name);
    normalizedStatus=status;
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
    // Paging I/O cannot query the filesystem for names. DEFAULT can refuse
    // before consulting the cache; try the already-cached normalized form.
    // Keep the first query's status for diagnostics and never fabricate a path.
    if(!NT_SUCCESS(status)){
        status=FltGetFileNameInformation(data,FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,&name);
    }
#endif
#ifdef SQ_REMOTE_FILESYSTEM_DIAGNOSTIC
    // MUP normalized names can carry redirector-specific prefixes and do not
    // necessarily match the explicit UNC scope. Use the independently queried
    // opened name at this client boundary, preserving the actual normalization
    // status and labelling the chosen name as opened. Local volume logic is unchanged.
    if(SqIsRemoteInstance(objects->Instance)){
        if(name){FltReleaseFileNameInformation(name);name=NULL;}
        status=FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_DEFAULT,&name);
        nameSource=2;
    }
#endif
    // A denied/nonexistent CREATE may not have a resolvable normalized final name.
    // Preserve a separately labelled opened name; never label it normalized.
    if(!NT_SUCCESS(status)){
        status=FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,&name);
        nameSource=2;
    }
    if(!NT_SUCCESS(status)){InterlockedIncrement64(&NameFailures);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    if(!IsWatched(&name->Name)){FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    if(InterlockedIncrement(&Allocated)>SQ_QUEUE_LIMIT){InterlockedDecrement(&Allocated);FltReleaseFileNameInformation(name);InterlockedIncrement64(&Dropped);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    record=Allocate(TRUE,sizeof(SQ_RECORD));
    if(!record){InterlockedDecrement(&Allocated);FltReleaseFileNameInformation(name);InterlockedIncrement64(&Dropped);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    record->Event.Version=SQ_PROTOCOL;record->Event.Size=sizeof(SQ_EVENT);record->Event.Instance=Instance;
    record->Event.Sequence=InterlockedIncrement64(&Sequence);
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&record->Event.ObservedUtc);
    record->Event.MonotonicTicks=KeQueryPerformanceCounter((PLARGE_INTEGER)&record->Event.MonotonicFrequency).QuadPart;
    record->Event.NameSource=nameSource;record->Event.NameStatus=normalizedStatus;
    record->Event.Major=data->Iopb->MajorFunction;record->Event.Minor=data->Iopb->MinorFunction;
#ifdef SQ_REMOTE_FILESYSTEM_DIAGNOSTIC
    if(SqIsRemoteInstance(objects->Instance))record->Event.Flags|=SQ_F_REMOTE_FILESYSTEM;
#endif
    if(FlagOn(data->Iopb->IrpFlags,IRP_PAGING_IO))record->Event.Flags|=SQ_F_PAGING;
    if(FLT_IS_FASTIO_OPERATION(data))record->Event.Flags|=SQ_F_FASTIO;
    if(data->Iopb->MajorFunction==IRP_MJ_SET_INFORMATION)record->Event.OperationClass=data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if(data->Iopb->MajorFunction==IRP_MJ_SET_SECURITY)record->Event.OperationClass=data->Iopb->Parameters.SetSecurity.SecurityInformation;
    if(data->Iopb->MajorFunction==IRP_MJ_CREATE){
        record->Event.CreateOptions=data->Iopb->Parameters.Create.Options;
        if(data->Iopb->Parameters.Create.SecurityContext)record->Event.DesiredAccess=data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    CopyText(record->Event.Path,&name->Name,&record->Event.Flags);
    FltReleaseFileNameInformation(name);
    CaptureActor(data,record);
    *context=record;return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
#ifdef SQ_POST_CREATE_DIAGNOSTIC
static FLT_PREOP_CALLBACK_STATUS PreOperation(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
{
    FLT_PREOP_CALLBACK_STATUS status=CapturePreOperation(data,objects,context);
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    if(DiagWantsCreate(data)
#ifdef SQ_REMOTE_FILESYSTEM_DIAGNOSTIC
        &&!SqIsRemoteInstance(objects->Instance)
#endif
        ){
        SQ_RECORD* record=(SQ_RECORD*)*context;
        if(!record){
            if(InterlockedIncrement(&Allocated)>SQ_QUEUE_LIMIT){InterlockedDecrement(&Allocated);return FLT_PREOP_SUCCESS_WITH_CALLBACK;}
            record=Allocate(TRUE,sizeof(*record));
            if(!record){InterlockedDecrement(&Allocated);return FLT_PREOP_SUCCESS_WITH_CALLBACK;}
            record->StDiagnosticOnly=TRUE;
        }
        record->StOriginalRequestedAccess=data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        record->StNameQualified=StQualifyPreCreate(data,&record->StMappedRequestedAccess);*context=record;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
#endif
    if(status==FLT_PREOP_SUCCESS_NO_CALLBACK&&DiagWantsCreate(data))return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    return status;
}
#endif
static FLT_POSTOP_CALLBACK_STATUS PostOperation(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID context,FLT_POST_OPERATION_FLAGS flags)
{
    SQ_RECORD* record=(SQ_RECORD*)context;
    UNREFERENCED_PARAMETER(objects);
#ifdef SQ_POST_CREATE_DIAGNOSTIC
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StPostCreate(data,objects,flags,record&&record->StNameQualified,record?record->StMappedRequestedAccess:0,record?record->StOriginalRequestedAccess:0);
    if(record&&record->StDiagnosticOnly){ReleaseRecord(record);record=NULL;}
#endif
    DiagPostCreate(data,objects,flags);
#endif
    if(record){
        KeQuerySystemTimePrecise((PLARGE_INTEGER)&record->Event.CompletedUtc);
        record->Event.Status=data->IoStatus.Status;record->Event.Information=data->IoStatus.Information;
        if(FlagOn(flags,FLTFL_POST_OPERATION_DRAINING))record->Event.Flags|=SQ_F_DRAINING;
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
        if(record->Deferred.Version)DeferredSubmit(record);else Enqueue(record);
#else
        Enqueue(record);
#endif
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}
static NTSTATUS Connect(PFLT_PORT port,PVOID serverCookie,PVOID connection,ULONG bytes,PVOID* cookie)
{
    UNREFERENCED_PARAMETER(serverCookie);UNREFERENCED_PARAMETER(connection);UNREFERENCED_PARAMETER(bytes);
#ifdef SQ_IMAGE_DIAGNOSTIC
    if(InterlockedCompareExchange(&DiagStopping,0,0))return STATUS_DELETE_PENDING;
#endif
    FltAcquirePushLockExclusive(&PortLock);
    if(PortShutdown||PortClosing||ClientPort||ConnectionSequence==MAXULONG_PTR){FltReleasePushLock(&PortLock);return STATUS_DEVICE_BUSY;}
    if(ConnectionSequence)ExReInitializeRundownProtection(&ConnectionCommands);
    else ExInitializeRundownProtection(&ConnectionCommands);
    KeClearEvent(&PortDetached);
    ActiveConnectionCookie=(PVOID)++ConnectionSequence;
    *cookie=ActiveConnectionCookie;ClientPort=port;
    FltReleasePushLock(&PortLock);return STATUS_SUCCESS;
}
static VOID DetachClient(PVOID cookie,BOOLEAN all)
{
    BOOLEAN close=FALSE,wait=FALSE;
    FltAcquirePushLockExclusive(&PortLock);
    if(ClientPort&&(all||cookie==ActiveConnectionCookie)){
        if(PortClosing)wait=all;
        else{PortClosing=TRUE;close=TRUE;}
    }
    FltReleasePushLock(&PortLock);
    if(wait){KeWaitForSingleObject(&PortDetached,Executive,KernelMode,FALSE,NULL);return;}
    if(!close)return;
    // Wait outside PortLock and any critical region. Existing command rundown
    // may include generated file I/O; never force-release its code or evidence.
    ExWaitForRundownProtectionRelease(&ConnectionCommands);
    FltAcquirePushLockExclusive(&PortLock);
    FltCloseClientPort(Filter,&ClientPort);ActiveConnectionCookie=NULL;PortClosing=FALSE;
    KeSetEvent(&PortDetached,IO_NO_INCREMENT,FALSE);
    FltReleasePushLock(&PortLock);
}
static VOID Disconnect(PVOID cookie)
{
    // Transport lifetime is separate from the driver's single capture epoch.
    // Keep bounded acquisition, expiry, raw records and operation pins alive.
    // Explicit STOP and unload remain terminal; reconnect resets no generation.
    DetachClient(cookie,FALSE);
}
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
// Reads the immutable blob pinned by the unacknowledged queue head. Candidate
// expiry releases the table's reference, not this operation's evidence. Require
// both the complete candidate key and the exact operation; never search by PID.
typedef struct _SQ_PINNED_REQUEST {ST_BOUND_REQUEST Key;ULONGLONG Instance,Sequence;} SQ_PINNED_REQUEST;
C_ASSERT(sizeof(SQ_PINNED_REQUEST)==88);
static NTSTATUS ReadPinnedActor(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    SQ_PINNED_REQUEST query;ST_BOUND_REPLY reply={0};ST_BLOB* blob=NULL;
    KIRQL old;BOOLEAN publication=FALSE;NTSTATUS status=STATUS_NOT_FOUND;
    if(inputBytes!=sizeof(query))return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&query,input,sizeof(query));
    if(query.Key.Version!=4||query.Key.Command!=22||query.Key.Schema!=3||
        !query.Key.Generation||!query.Key.Id||!query.Key.Pid||!query.Key.Created||!query.Instance||!query.Sequence||
        (query.Key.Operation!=10&&query.Key.Operation!=13&&query.Key.Operation!=26&&query.Key.Operation!=27)||query.Key.Length>ST_CHUNK||
        ((query.Key.Operation==13||query.Key.Operation==26||query.Key.Operation==27)&&(query.Key.Offset||query.Key.Length)))return STATUS_INVALID_PARAMETER;
    if(!output||outputBytes<(query.Key.Operation==27?sizeof(ST_PROCESS_METADATA_REPLY):query.Key.Operation==26?sizeof(ST_SOURCE_IDENTITY_REPLY):sizeof(reply)+query.Key.Length))return STATUS_BUFFER_TOO_SMALL;
    if(!StAcquire())return STATUS_DELETE_PENDING;
    __try{
        if(!ExAcquireRundownProtection(&StPublicationRundown)){status=STATUS_DELETE_PENDING;__leave;}
        publication=TRUE;InterlockedIncrement(&StPublicationInFlight);
        if(!InterlockedCompareExchange(&StEnabled,0,0)){status=STATUS_DELETE_PENDING;__leave;}
        KeAcquireSpinLock(&QueueLock,&old);
        if(!IsListEmpty(&Queue)){
            SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);SB_BINDING* b=&head->StBinding;
            if(head->StPinnedBlob&&b->Flags==1&&head->Event.Instance==query.Instance&&head->Event.Sequence==query.Sequence&&
                b->EventInstance==query.Instance&&b->EventSequence==query.Sequence&&
                RtlEqualMemory(&b->Provider,&query.Key.Provider,sizeof(UUID))&&
                b->Generation==query.Key.Generation&&b->Candidate==query.Key.Id&&b->Pid==query.Key.Pid&&b->Created==query.Key.Created){
                blob=head->StPinnedBlob;InterlockedIncrement(&blob->References);
            }
        }
        KeReleaseSpinLock(&QueueLock,old);
        if(!blob)__leave;
        if(query.Key.Operation==27){StProcessMetadataReply(blob,&query.Key,query.Instance,query.Sequence,output);*returned=sizeof(ST_PROCESS_METADATA_REPLY);status=STATUS_SUCCESS;__leave;}
        if(query.Key.Operation==26){ST_SOURCE_IDENTITY_REPLY source;StSourceIdentityReply(blob,&query.Key,query.Instance,query.Sequence,&source);RtlCopyMemory(output,&source,sizeof(source));*returned=sizeof(source);status=STATUS_SUCCESS;__leave;}
        if(query.Key.Offset>blob->Length||query.Key.Length>blob->Length-query.Key.Offset){status=STATUS_INVALID_PARAMETER;__leave;}
        if(query.Key.Operation==10&&query.Key.Length){status=StPausePublication();if(!NT_SUCCESS(status))__leave;}
        reply.Reply.Version=3;reply.Reply.Size=sizeof(reply);reply.Reply.TotalBytes=blob->Length;
        reply.Reply.Offset=query.Key.Offset;reply.Reply.Count=query.Key.Length;reply.Reply.Flags=1|4|8;
        reply.Reply.Reserved=blob->RequestedAccess;reply.Reply.Id=query.Key.Id;reply.Reply.Pid=query.Key.Pid;reply.Reply.Created=query.Key.Created;
        reply.Reply.FileId=blob->FileId;reply.Reply.CreatedUtc=blob->CreatedUtc;reply.Reply.ModifiedUtc=blob->ModifiedUtc;reply.Reply.ChangedUtc=blob->ChangedUtc;
        reply.Reply.CopyStartedUtc=blob->CopyStartedUtc;reply.Reply.CopyEndedUtc=blob->CopyEndedUtc;
        reply.Reply.OriginalRequestedAccess=blob->OriginalRequestedAccess;reply.Reply.QualificationVersion=blob->QualificationVersion;reply.Reply.CreateStatus=blob->CreateStatus;
        reply.Provider=query.Key.Provider;reply.Generation=query.Key.Generation;
        RtlCopyMemory(output,&reply,sizeof(reply));
        if(query.Key.Length)RtlCopyMemory((PUCHAR)output+sizeof(reply),blob->Bytes+query.Key.Offset,query.Key.Length);
        *returned=sizeof(reply)+query.Key.Length;status=STATUS_SUCCESS;
    }__finally{
        if(blob)StRelease(blob);
        if(publication){InterlockedDecrement(&StPublicationInFlight);ExReleaseRundownProtection(&StPublicationRundown);}
        ExReleaseRundownProtection(&StRundown);
    }
    return status;
}
#endif
static NTSTATUS MessageCore(PVOID cookie,PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    SQ_MESSAGE* message;
    NTSTATUS status=STATUS_INVALID_PARAMETER;
    UNREFERENCED_PARAMETER(cookie);*returned=0;
    if(!input || inputBytes<2*sizeof(ULONG))return STATUS_INVALID_PARAMETER;
    message=Allocate(FALSE,sizeof(SQ_MESSAGE));
    if(!message)return STATUS_INSUFFICIENT_RESOURCES;
    __try {
        RtlCopyMemory(message,input,min(inputBytes,sizeof(SQ_MESSAGE)));
        if(message->Version!=SQ_PROTOCOL)__leave;
#ifdef SQ_IMAGE_DIAGNOSTIC
        if(message->Command>=SQ_DIAG_START&&message->Command<=SQ_DIAG_STOP){status=DiagMessage(message->Command,inputBytes,output,outputBytes,returned);__leave;}
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        if(message->Command==SQ_GET_EXACT_ACQUISITION_ORDERING){
            ST_ORDERING_REQUEST query;ST_ORDERING_HEALTH snapshot={0};KIRQL old;ULONG i;BOOLEAN found=FALSE;
            if(inputBytes!=sizeof(query)||!output||outputBytes<sizeof(snapshot))__leave;RtlCopyMemory(&query,input,sizeof(query));
            if(query.Epoch!=Instance||!query.Candidate||!query.Generation||!query.Pid||!query.Created||!RtlEqualMemory(&query.Provider,&SbHealth.Provider,sizeof(UUID))){status=STATUS_NOT_FOUND;__leave;}
            KeAcquireSpinLock(&StLock,&old);
            for(i=0;i<ST_SLOTS;i++){
                const ST_ENTRY* entry=&StEntries[i];
                if(entry->File&&entry->Id==query.Candidate&&entry->ProcessGeneration==query.Generation&&entry->Pid==query.Pid&&entry->Created==query.Created){
                    snapshot=StOrdering;snapshot.Candidate=entry->Id;snapshot.Generation=entry->ProcessGeneration;snapshot.Pid=entry->Pid;snapshot.Created=entry->Created;
                    snapshot.BeginQpc=entry->PostBeginQpc;snapshot.BindQpc=entry->BindQpc;snapshot.TerminalQpc=entry->PostTerminalQpc;snapshot.Phase=entry->BindPhase;snapshot.Active=entry->BindActive;found=TRUE;break;
                }
            }
            KeReleaseSpinLock(&StLock,old);
            if(!found){status=STATUS_NOT_FOUND;__leave;}
            snapshot.Version=1;snapshot.Size=sizeof(snapshot);snapshot.Provider=SbHealth.Provider;snapshot.Epoch=Instance;
            RtlCopyMemory(output,&snapshot,sizeof(snapshot));*returned=sizeof(snapshot);status=STATUS_SUCCESS;__leave;
        }
        if(message->Command==SQ_GET_ACQUISITION_ORDERING){
            ST_ORDERING_HEALTH snapshot;KIRQL old;
            if(inputBytes!=8||!output||outputBytes<sizeof(snapshot))__leave;
            KeAcquireSpinLock(&StLock,&old);snapshot=StOrdering;KeReleaseSpinLock(&StLock,old);
            snapshot.Version=1;snapshot.Size=sizeof(snapshot);snapshot.Provider=SbHealth.Provider;snapshot.Epoch=Instance;
            RtlCopyMemory(output,&snapshot,sizeof(snapshot));*returned=sizeof(snapshot);status=STATUS_SUCCESS;__leave;
        }
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
        if(message->Command==SQ_ARM_ACQUISITION_FAULT||message->Command==SQ_GET_ACQUISITION_FAULT_HEALTH){status=AfMessage(input,inputBytes,output,outputBytes,returned,Instance);__leave;}
#endif
        if(message->Command==SQ_GET_NEGATIVE_ACQUISITION_HEALTH){
            SQ_NEGATIVE_ACQUISITION_HEALTH snapshot={0};KIRQL old;ULONG i;
            if(inputBytes!=8||!output||outputBytes<sizeof(snapshot))__leave;
            snapshot.Version=1;snapshot.Size=sizeof(snapshot);snapshot.Provider=SbHealth.Provider;snapshot.Epoch=Instance;snapshot.Capacity=ST_NEG_CAPACITY;
            KeAcquireSpinLock(&StLock,&old);
            snapshot.NextAssociation=StNegativeNext;snapshot.ReferencesTaken=StNegativeReferences;snapshot.ReferencesReleased=StNegativeReleased;
            snapshot.GapCount=StNegativeGapCount;snapshot.GapQpc=StNegativeGapQpc;
            for(i=0;i<ST_NEG_CAPACITY;i++)if(StNegatives[i].File){snapshot.Live++;if(StNegatives[i].BindAttempted)snapshot.BindAttempted++;}
            KeReleaseSpinLock(&StLock,old);
            RtlCopyMemory(output,&snapshot,sizeof(snapshot));*returned=sizeof(snapshot);status=STATUS_SUCCESS;__leave;
        }
        if(message->Command==SQ_GET_ACQUISITION_CAPABILITIES){
            SQ_ACQUISITION_CAPABILITIES capabilities={0};
            if(inputBytes!=8||!output||outputBytes<sizeof(capabilities))__leave;
            capabilities.Version=1;capabilities.Size=sizeof(capabilities);capabilities.Provider=SbHealth.Provider;
            capabilities.Epoch=Instance;capabilities.OutcomeVersion=1;capabilities.OutcomeSize=sizeof(SQ_ACQUISITION_OUTCOME);
            // The default lab build keeps discovery off. Explicit managed
            // qualification builds advertise the immutable companion protocol.
#ifdef SQ_ACQUISITION_OUTCOME_ADVERTISED
            capabilities.Flags=1;
#else
            capabilities.Flags=0;
#endif
            RtlCopyMemory(output,&capabilities,sizeof(capabilities));*returned=sizeof(capabilities);status=STATUS_SUCCESS;__leave;
        }
        if(message->Command==SQ_GET_ACQUISITION_OUTCOME){
            SQ_ACQUISITION_REQUEST query;SQ_ACQUISITION_OUTCOME snapshot={0};KIRQL old;BOOLEAN found=FALSE;
            if(inputBytes!=sizeof(query)||!output||outputBytes<sizeof(snapshot))__leave;
            RtlCopyMemory(&query,input,sizeof(query));
            if(!query.Instance||!query.Sequence||query.Epoch!=Instance||!RtlEqualMemory(&query.Provider,&SbHealth.Provider,sizeof(UUID))){status=STATUS_NOT_FOUND;__leave;}
            KeAcquireSpinLock(&QueueLock,&old);
            if(!IsListEmpty(&Queue)){
                const SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);
                if(head->Event.Instance==query.Instance&&head->Event.Sequence==query.Sequence){snapshot=head->AcquisitionOutcome;found=TRUE;}
            }
            KeReleaseSpinLock(&QueueLock,old);
            if(found){RtlCopyMemory(output,&snapshot,sizeof(snapshot));*returned=sizeof(snapshot);status=STATUS_SUCCESS;}
            else status=STATUS_NOT_FOUND;
            __leave;
        }
#endif
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
        if(message->Command>=29&&message->Command<=33){status=CfMessage(input,inputBytes,output,outputBytes,returned,InterlockedCompareExchange(&StEnabled,0,0)!=0);__leave;}
#endif
        if(message->Command==22){status=ReadPinnedActor(input,inputBytes,output,outputBytes,returned);__leave;}
#ifdef SQ_APC_PIN_DIAGNOSTIC
        if(message->Command==36){status=StMessage(input,inputBytes,output,outputBytes,returned,Instance);__leave;}
#endif
        if(message->Command==18){
            SB_BINDING binding={0};ULONGLONG key[2];KIRQL old;BOOLEAN found=FALSE;
            if(inputBytes!=40||!output||outputBytes<sizeof(binding))__leave;
            if(!RtlEqualMemory((PUCHAR)message+24,&SbHealth.Provider,sizeof(UUID))){status=STATUS_NOT_FOUND;__leave;}
            RtlCopyMemory(key,message->Root,sizeof(key));
            KeAcquireSpinLock(&QueueLock,&old);
            if(!IsListEmpty(&Queue)){
                SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);
                if(head->Event.Instance==key[0]&&head->Event.Sequence==key[1]){binding=head->StBinding;found=TRUE;}
            }
            KeReleaseSpinLock(&QueueLock,old);
            if(!found){status=STATUS_NOT_FOUND;__leave;}
            RtlCopyMemory(output,&binding,sizeof(binding));*returned=sizeof(binding);status=STATUS_SUCCESS;__leave;
        }
        if((message->Command>=10&&message->Command<=17)||message->Command==19||message->Command==20||message->Command==21||message->Command==24||message->Command==25||message->Command==28){status=StMessage(message,inputBytes,output,outputBytes,returned,Instance);__leave;}
#endif
#endif
        if(message->Command==SQ_SET_PATHS){
            SQ_PATH_SET* replacement=NULL;SQ_PATH_SET* previous;ULONG count,i;
            if(inputBytes<12)__leave;
            RtlCopyMemory(&count,(PUCHAR)input+8,sizeof(count));
            if(count>SQ_MAX_PATHS||inputBytes!=12+count*SQ_PATH_CHARS*sizeof(WCHAR))__leave;
            replacement=Allocate(FALSE,sizeof(SQ_PATH_SET));
            if(!replacement){status=STATUS_INSUFFICIENT_RESOURCES;__leave;}
            __try{
                replacement->Count=count;RtlCopyMemory(replacement->Paths,(PUCHAR)input+12,count*SQ_PATH_CHARS*sizeof(WCHAR));
                for(i=0;i<count;i++){
                    SIZE_T chars;
                    if(!NT_SUCCESS(RtlStringCchLengthW(replacement->Paths[i],SQ_PATH_CHARS,&chars))||chars<12||chars>=SQ_PATH_CHARS-1||wcsncmp(replacement->Paths[i],L"\\Device\\",8)!=0)__leave;
                }
                FltAcquirePushLockExclusive(&RootLock);
                previous=ExactPaths;ExactPaths=replacement;replacement=NULL;Root.Length=0;
                InterlockedExchange(&RootConfigured,count?1:0);
                FltReleasePushLock(&RootLock);
                if(previous)ExFreePoolWithTag(previous,SQ_TAG);status=STATUS_SUCCESS;
            }__finally{if(replacement)ExFreePoolWithTag(replacement,SQ_TAG);}
        }else if(message->Command==SQ_SET_ROOT){
            SIZE_T chars;
            if(inputBytes!=sizeof(SQ_MESSAGE) || !NT_SUCCESS(RtlStringCchLengthW(message->Root,SQ_PATH_CHARS,&chars)) || chars<12 ||
               chars>=SQ_PATH_CHARS-1 || message->Root[chars-1]!=L'\\' || wcsncmp(message->Root,L"\\Device\\",8)!=0)__leave;
            FltAcquirePushLockExclusive(&RootLock);
            RtlCopyMemory(RootBuffer,message->Root,(chars+1)*sizeof(WCHAR));RtlInitUnicodeString(&Root,RootBuffer);
            InterlockedExchange(&RootConfigured,1);
            FltReleasePushLock(&RootLock);status=STATUS_SUCCESS;
        }else if(message->Command==SQ_GET_HEALTH){
            SQ_HEALTH health={0};
            if(!output || outputBytes<sizeof(health)){status=STATUS_BUFFER_TOO_SMALL;__leave;}
            health.Version=SQ_PROTOCOL;health.Size=sizeof(health);health.Instance=Instance;
            health.Sequence=InterlockedCompareExchange64(&Sequence,0,0);health.Dropped=InterlockedCompareExchange64(&Dropped,0,0);
            health.NameFailures=InterlockedCompareExchange64(&NameFailures,0,0);health.Queued=InterlockedCompareExchange(&Queued,0,0);health.RootConfigured=InterlockedCompareExchange(&RootConfigured,0,0);
            RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);status=STATUS_SUCCESS;
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
        }else if(message->Command==SQ_GET_DEFERRED_TOKEN_CONTEXT){
            KIRQL irql;SQ_DEFERRED_TOKEN_CONTEXT* snapshot;ULONGLONG identity[2];BOOLEAN found=FALSE;
            if(inputBytes!=24)__leave;
            if(!output||outputBytes!=sizeof(SQ_DEFERRED_TOKEN_CONTEXT)){status=STATUS_BUFFER_TOO_SMALL;__leave;}
            RtlCopyMemory(identity,message->Root,sizeof(identity));
            snapshot=Allocate(TRUE,sizeof(*snapshot));
            if(!snapshot){status=STATUS_INSUFFICIENT_RESOURCES;__leave;}
            KeAcquireSpinLock(&QueueLock,&irql);
            if(!IsListEmpty(&Queue)){
                const SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);
                if(head->Event.Instance==identity[0]&&head->Event.Sequence==identity[1]&&head->Deferred.Version){RtlCopyMemory(snapshot,&head->Deferred,sizeof(*snapshot));found=TRUE;}
            }
            KeReleaseSpinLock(&QueueLock,irql);
            __try{if(found){RtlCopyMemory(output,snapshot,sizeof(*snapshot));*returned=sizeof(*snapshot);status=STATUS_SUCCESS;}else status=STATUS_NOT_FOUND;}
            __finally{ExFreePoolWithTag(snapshot,SQ_TAG);}
#endif
        }else if(message->Command==SQ_GET_THREAD_CONTEXT){
            KIRQL irql;SQ_CONTEXT_REPLY* snapshot;ULONGLONG identity[2];BOOLEAN found=FALSE;
            if(inputBytes!=24)__leave;
            if(!output||outputBytes!=sizeof(SQ_CONTEXT_REPLY)){status=STATUS_BUFFER_TOO_SMALL;__leave;}
            RtlCopyMemory(identity,message->Root,sizeof(identity));
            snapshot=Allocate(TRUE,sizeof(SQ_CONTEXT_REPLY));
            if(!snapshot){status=STATUS_INSUFFICIENT_RESOURCES;__leave;}
            KeAcquireSpinLock(&QueueLock,&irql);
            if(!IsListEmpty(&Queue)){
                SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);
                if(head->Event.Instance==identity[0]&&head->Event.Sequence==identity[1]){RtlCopyMemory(&snapshot->Event,&head->Event,sizeof(SQ_EVENT));RtlCopyMemory(&snapshot->Context,&head->ThreadContext,sizeof(SQ_THREAD_CONTEXT));found=TRUE;}
            }
            KeReleaseSpinLock(&QueueLock,irql);
            __try{if(found){RtlCopyMemory(output,snapshot,sizeof(SQ_CONTEXT_REPLY));*returned=sizeof(SQ_CONTEXT_REPLY);status=STATUS_SUCCESS;}else status=STATUS_NOT_FOUND;}
            __finally{ExFreePoolWithTag(snapshot,SQ_TAG);}
        }else if(message->Command==SQ_GET_EVENT){
            KIRQL irql;SQ_EVENT* snapshot;BOOLEAN found=FALSE;
            if(!output || outputBytes<sizeof(SQ_EVENT)){status=STATUS_BUFFER_TOO_SMALL;__leave;}
            snapshot=Allocate(TRUE,sizeof(SQ_EVENT));
            if(!snapshot){status=STATUS_INSUFFICIENT_RESOURCES;__leave;}
            KeAcquireSpinLock(&QueueLock,&irql);
            if(!IsListEmpty(&Queue)){SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);RtlCopyMemory(snapshot,&head->Event,sizeof(SQ_EVENT));found=TRUE;}
            KeReleaseSpinLock(&QueueLock,irql);
            __try {if(found){RtlCopyMemory(output,snapshot,sizeof(SQ_EVENT));*returned=sizeof(SQ_EVENT);status=STATUS_SUCCESS;}else status=STATUS_NO_MORE_ENTRIES;}
            __finally {ExFreePoolWithTag(snapshot,SQ_TAG);}
        }else if(message->Command==SQ_ACK_EVENT){
            KIRQL irql;SQ_RECORD* record=NULL;ULONGLONG identity[2];
            if(inputBytes!=24)__leave;
            RtlCopyMemory(identity,message->Root,sizeof(identity));
            KeAcquireSpinLock(&QueueLock,&irql);
            if(!IsListEmpty(&Queue)){
                SQ_RECORD* head=CONTAINING_RECORD(Queue.Flink,SQ_RECORD,Link);
                if(head->Event.Instance==identity[0]&&head->Event.Sequence==identity[1]){record=CONTAINING_RECORD(RemoveHeadList(&Queue),SQ_RECORD,Link);Queued--;}
            }
            KeReleaseSpinLock(&QueueLock,irql);
            if(record){ReleaseRecord(record);status=STATUS_SUCCESS;}
        }
    }__except(EXCEPTION_EXECUTE_HANDLER){status=GetExceptionCode();}
    ExFreePoolWithTag(message,SQ_TAG);return status;
}
static NTSTATUS Message(PVOID cookie,PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    NTSTATUS status=STATUS_PORT_DISCONNECTED;BOOLEAN acquired=FALSE;
    // Only connection admission runs under the lock. Expensive commands retain
    // a separate rundown lease without disabling normal APC delivery. Closing
    // rejects new commands and waits outside the lock; no storage is reused
    // until all admitted commands and FltCloseClientPort have completed.
    FltAcquirePushLockShared(&PortLock);
    if(cookie&&cookie==ActiveConnectionCookie&&ClientPort&&!PortClosing)
        acquired=ExAcquireRundownProtection(&ConnectionCommands);
    FltReleasePushLock(&PortLock);
    if(!acquired){*returned=0;return status;}
    __try{status=MessageCore(cookie,input,inputBytes,output,outputBytes,returned);}
    __finally{ExReleaseRundownProtection(&ConnectionCommands);}
    return status;
}
static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS objects,FLT_INSTANCE_SETUP_FLAGS flags,DEVICE_TYPE device,FLT_FILESYSTEM_TYPE filesystem)
{
    UNREFERENCED_PARAMETER(flags);UNREFERENCED_PARAMETER(device);
    BOOLEAN remote=FALSE;
#ifdef SQ_REMOTE_FILESYSTEM_DIAGNOSTIC
    remote=filesystem==FLT_FSTYPE_MUP&&device==FILE_DEVICE_NETWORK_FILE_SYSTEM;
#endif
    if(filesystem!=FLT_FSTYPE_NTFS&&!remote)return STATUS_FLT_DO_NOT_ATTACH;
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    SqInitializeVolumeIdentity(objects,remote);
#else
    UNREFERENCED_PARAMETER(objects);
#endif
    return STATUS_SUCCESS;
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    FltAcquirePushLockExclusive(&PortLock);PortShutdown=TRUE;FltReleasePushLock(&PortLock);
#ifdef SQ_IMAGE_DIAGNOSTIC
    {NTSTATUS status=DiagUnregister();if(status!=STATUS_SUCCESS)return status;}
#endif
    FltCloseCommunicationPort(ServerPort);DetachClient(NULL,TRUE);
    FltUnregisterFilter(Filter);FltDeletePushLock(&PortLock);
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
    DeferredStop();
#endif
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StFinishShutdown();
#endif
    FltDeletePushLock(&RootLock);
    if(ExactPaths)ExFreePoolWithTag(ExactPaths,SQ_TAG);
    while(!IsListEmpty(&Queue)){SQ_RECORD* record=CONTAINING_RECORD(RemoveHeadList(&Queue),SQ_RECORD,Link);ReleaseRecord(record);}
    return STATUS_SUCCESS;
}
static const FLT_OPERATION_REGISTRATION Operations[]={
#ifdef SQ_POST_CREATE_DIAGNOSTIC
    {IRP_MJ_CLEANUP,0,DiagCleanup,NULL},
#endif
    {IRP_MJ_CREATE,0,PreOperation,PostOperation},
    {IRP_MJ_READ,0,PreOperation,PostOperation},
    {IRP_MJ_WRITE,0,PreOperation,PostOperation},
    {IRP_MJ_SET_INFORMATION,0,PreOperation,PostOperation},
    {IRP_MJ_SET_SECURITY,0,PreOperation,PostOperation},
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,0,PreOperation,PostOperation},
    {IRP_MJ_OPERATION_END}
};
static const FLT_REGISTRATION Registration={sizeof(FLT_REGISTRATION),FLT_REGISTRATION_VERSION,0,
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    SourceVolumeContexts,
#else
    NULL,
#endif
    Operations,Unload,InstanceSetup};
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
    NTSTATUS status;PSECURITY_DESCRIPTOR security=NULL;OBJECT_ATTRIBUTES attributes;UNICODE_STRING name;
    UNREFERENCED_PARAMETER(registry);
#ifdef SQ_IMAGE_DIAGNOSTIC
    KeInitializeSpinLock(&DiagLock);DiagHealth.Version=1;DiagHealth.Size=sizeof(DiagHealth);
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    KeInitializeSpinLock(&StLock);ExInitializeRundownProtection(&StRundown);ExInitializeRundownProtection(&StPublicationRundown);
    KeInitializeEvent(&StWorkerStop,NotificationEvent,FALSE);KeInitializeEvent(&StStopComplete,NotificationEvent,FALSE);KeInitializeEvent(&StTestPublicationGate,NotificationEvent,FALSE);
    status=SbInitialize();if(!NT_SUCCESS(status))return status;
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    CfInitialize();
#endif
#endif
#endif
    FltInitializePushLock(&RootLock);FltInitializePushLock(&PortLock);KeInitializeEvent(&PortDetached,NotificationEvent,TRUE);KeInitializeSpinLock(&QueueLock);InitializeListHead(&Queue);
    Instance=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    status=FltRegisterFilter(driver,&Registration,&Filter);if(!NT_SUCCESS(status)){FltDeletePushLock(&PortLock);FltDeletePushLock(&RootLock);return status;}
    status=FltBuildDefaultSecurityDescriptor(&security,FLT_PORT_ALL_ACCESS);
    if(NT_SUCCESS(status)){
        RtlInitUnicodeString(&name,SQ_PORT_NAME);InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,security);
        status=FltCreateCommunicationPort(Filter,&ServerPort,&attributes,NULL,Connect,Disconnect,Message,1);FltFreeSecurityDescriptor(security);
    }
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
    if(NT_SUCCESS(status))status=DeferredStart();
#endif
    if(NT_SUCCESS(status))status=FltStartFiltering(Filter);
#ifdef SQ_IMAGE_DIAGNOSTIC
    if(NT_SUCCESS(status))status=DiagRegister();
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    if(NT_SUCCESS(status))status=StStartWorker();
#endif
#endif
    if(!NT_SUCCESS(status)){
#ifdef SQ_IMAGE_DIAGNOSTIC
        if(DiagImageRegistered||DiagProcessRegistered)DiagUnregister();
#endif
        FltAcquirePushLockExclusive(&PortLock);PortShutdown=TRUE;FltReleasePushLock(&PortLock);
        if(ServerPort)FltCloseCommunicationPort(ServerPort);DetachClient(NULL,TRUE);FltUnregisterFilter(Filter);
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
        DeferredStop();
        while(!IsListEmpty(&Queue)){SQ_RECORD* record=CONTAINING_RECORD(RemoveHeadList(&Queue),SQ_RECORD,Link);ReleaseRecord(record);}
#endif
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
        StFinishShutdown();
#endif
        FltDeletePushLock(&PortLock);FltDeletePushLock(&RootLock);
    }
    return status;
}
