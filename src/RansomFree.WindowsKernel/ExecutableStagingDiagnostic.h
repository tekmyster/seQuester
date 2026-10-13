#pragma once
#include "ActorBindingDiagnostic.h"
#include "PrimaryImageHeader.h"
#include "SourceVolumeIdentity.h"
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
#include "CreationFaultDiagnostic.h"
#endif
#include "ProcessCreationMetadata.h"
// Explicit lab-only executable staging. Not enabled in ordinary driver builds.
// Reads only successful, read-capable executable-open candidates. Process/image
// notifications do no file I/O; copied data is published only after exact binding.
#define ST_TAG 'bSqS'
#define ST_SLOTS 128
// Bound all qualification/copy work; DLLs are rejected by header before full copy.
// Metadata and byte credit remain independently bounded. A burst of short-lived
// processes retains operation-owned snapshots until durable intake; 64 entries
// left no headroom for 64 actors plus existing executable candidates.
#define ST_MAX_INFLIGHT 32
#define ST_MAX_FULL_COPIES 16
#define ST_MAX_IMAGE (8u*1024u*1024u)
#define ST_MAX_BYTES (64u*1024u*1024u)
#define ST_CHUNK 65536u
#define ST_NOTICE_CAPACITY 4096u
typedef struct _ST_BLOB {
    volatile LONG References;
    ULONG Length;
    ULONG RequestedAccess, OriginalRequestedAccess, QualificationVersion, CreateStatus;
    PUCHAR Bytes;
    ULONGLONG FileId;
    LONGLONG CreatedUtc, ModifiedUtc, ChangedUtc, CopyStartedUtc, CopyEndedUtc;
    SQ_VOLUME_IDENTITY SourceVolume;
    PM_OBJECT* ProcessMetadata;
    ULONG ProcessMetadataState;
} ST_BLOB;
typedef struct _ST_ENTRY {
    PFILE_OBJECT File;
    ST_BLOB* Blob;
    PM_OBJECT* ProcessMetadata;
    ULONG ProcessMetadataState;
    ULONGLONG Id, Pid, Created, Deadline, ProcessGeneration, ReadySequence;
    BOOLEAN Exited, Counted;
    ULONGLONG FileId;
    ULONG Length, OriginalRequestedAccess, MappedRequestedAccess, QualificationVersion, CreateStatus;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    ULONG PostPhase,PostActive;
    ULONGLONG PostBeginQpc,PostTerminalQpc;
    ULONG BindPhase,BindActive;
    ULONGLONG BindQpc;
#endif
} ST_ENTRY;
// Kind: 1 admitted, 2 ready, 3 process-bound, 4 exited, 5 ACK, 6 expired,
// 7 unbound cleanup, 8 capacity eviction, 9 STOP, 10 candidate failure,
// 11 unbound admission skip, 12 aggregate collection failure observation.
typedef struct _ST_NOTICE {
    ULONG Version, Size, Kind, Reason, Status, Flags, OriginalAccess, MappedAccess, QualificationVersion, CreateStatus;
    ULONGLONG Sequence, Id, Pid, Created, FileId, Length, Monotonic, ObservedUtc;
    ULONG EmissionIrql, Reserved;
} ST_NOTICE;
C_ASSERT(sizeof(ST_NOTICE)==112);
typedef struct _ST_REQUEST {
    ULONG Version, Command;
    ULONGLONG Pid, Created, Id;
    ULONG Offset, Length;
} ST_REQUEST;
C_ASSERT(sizeof(ST_REQUEST)==40);
typedef struct _ST_BOUND_REQUEST {
    ULONG Version,Command;
    UUID Provider;
    ULONGLONG Generation,Id,Pid,Created;
    ULONG Offset,Length,Operation,Schema;
} ST_BOUND_REQUEST;
C_ASSERT(sizeof(ST_BOUND_REQUEST)==72);
// User-mode persisted-copy claims, not kernel-verified content hashes. Terminal
// receipts are bounded separately from payload buffers and live process entries.
#define ST_ACK_CAPACITY 256u
#define ST_ACK_TTL (300ULL*10000000ULL)
typedef struct _ST_DURABLE_ACK {
    ST_BOUND_REQUEST Key;
    ULONG ByteLength,ClaimVersion;
    UCHAR Sha256[32];
    UUID Receipt;
    UCHAR SnapshotIdentitySha256[32];
} ST_DURABLE_ACK;
C_ASSERT(sizeof(ST_DURABLE_ACK)==160);
typedef struct _ST_ACK_ENTRY {ST_DURABLE_ACK Claim;ULONGLONG Deadline;} ST_ACK_ENTRY;
static ST_ACK_ENTRY StAcknowledgements[ST_ACK_CAPACITY];
typedef struct _ST_REPLY {
    ULONG Version, Size, TotalBytes, Offset, Count, Flags, Status, Reserved;
    ULONGLONG Id, Pid, Created, FileId;
    LONGLONG CreatedUtc, ModifiedUtc, ChangedUtc, CopyStartedUtc, CopyEndedUtc;
    ULONG OriginalRequestedAccess, QualificationVersion, CreateStatus, Reserved2;
} ST_REPLY;
C_ASSERT(sizeof(ST_REPLY)==120);
typedef struct _ST_BOUND_REPLY {ST_REPLY Reply;UUID Provider;ULONGLONG Generation;} ST_BOUND_REPLY;
C_ASSERT(sizeof(ST_BOUND_REPLY)==144);
// Additive metadata operation 26. Existing byte/chunk replies remain unchanged.
typedef struct _ST_SOURCE_IDENTITY_REPLY {
    ULONG Version,Size,QueryStatus,Flags;
    UUID Provider;
    ULONGLONG Generation,Candidate,Pid,Created,FileId;
    WCHAR VolumeName[SQ_VOLUME_CHARS];
    ULONG NameBytes,Reserved;
    ULONGLONG OperationInstance,OperationSequence;
} ST_SOURCE_IDENTITY_REPLY;
C_ASSERT(sizeof(ST_SOURCE_IDENTITY_REPLY)==224);
static VOID StSourceIdentityReply(const ST_BLOB* blob,const ST_BOUND_REQUEST* key,ULONGLONG instance,ULONGLONG sequence,ST_SOURCE_IDENTITY_REPLY* reply)
{
    RtlZeroMemory(reply,sizeof(*reply));reply->Version=1;reply->Size=sizeof(*reply);
    reply->QueryStatus=(ULONG)blob->SourceVolume.Status;reply->Flags=NT_SUCCESS(blob->SourceVolume.Status)?1:0;
    reply->Provider=key->Provider;reply->Generation=key->Generation;reply->Candidate=key->Id;reply->Pid=key->Pid;reply->Created=key->Created;reply->FileId=blob->FileId;
    reply->NameBytes=blob->SourceVolume.NameBytes;RtlCopyMemory(reply->VolumeName,blob->SourceVolume.Name,sizeof(reply->VolumeName));
    reply->OperationInstance=instance;reply->OperationSequence=sequence;
}
// Operation 27: a separately versioned process-creation companion. No large
// local reply on the kernel stack; caller has validated the output buffer.
typedef struct _ST_PROCESS_METADATA_REPLY {
    ULONG Version,Size,QueryStatus,Reserved;
    UUID Provider;
    ULONGLONG Generation,Candidate,Pid,Created,OperationInstance,OperationSequence;
    PM_DATA Data;
} ST_PROCESS_METADATA_REPLY;
C_ASSERT(sizeof(ST_PROCESS_METADATA_REPLY)==5304);
static VOID StProcessMetadataReply(const ST_BLOB* blob,const ST_BOUND_REQUEST* key,ULONGLONG instance,ULONGLONG sequence,PVOID output)
{
    ST_PROCESS_METADATA_REPLY* reply=(ST_PROCESS_METADATA_REPLY*)output;
    RtlZeroMemory(reply,sizeof(*reply));reply->Version=1;reply->Size=sizeof(*reply);
    reply->Provider=key->Provider;reply->Generation=key->Generation;reply->Candidate=key->Id;reply->Pid=key->Pid;reply->Created=key->Created;
    reply->OperationInstance=instance;reply->OperationSequence=sequence;
    if(blob->ProcessMetadata)reply->Data=blob->ProcessMetadata->Data;
    else {reply->QueryStatus=(ULONG)(blob->ProcessMetadataState==2||blob->ProcessMetadataState==3?STATUS_INSUFFICIENT_RESOURCES:STATUS_NOT_FOUND);reply->Data.Version=1;reply->Data.Size=sizeof(reply->Data);reply->Data.CaptureStatus=reply->QueryStatus;reply->Data.Flags=blob->ProcessMetadataState;}
}
typedef struct _ST_SLOT_VIEW {
    ULONGLONG Id, Pid, Created, Deadline;
    ULONG Ready, Exited;
    ULONGLONG FileId;
    ULONG OriginalRequestedAccess, MappedRequestedAccess, QualificationVersion, CreateStatus;
} ST_SLOT_VIEW;
typedef struct _ST_TABLE_VIEW {
    ULONG Version, Size;
    ST_SLOT_VIEW Slots[ST_SLOTS];
} ST_TABLE_VIEW;
C_ASSERT(sizeof(ST_TABLE_VIEW)==8200);
typedef struct _ST_HEALTH {
    ULONG Version, Size, Enabled, InFlight, Live, LastMappedRequestedAccess;
    ULONGLONG Bytes, PeakBytes, Reads, ReadFailures, ProvisionalEntries, Matched, Released, Acks, Expired, PoolDrops;
    ULONGLONG Skipped, ReadCalls;
    ULONG LastStatus, LastReason;
    ULONGLONG BoundBuffersReady;
    ULONGLONG UnboundEvictions, DuplicateDrops;
    ULONG MetadataSlots, MaxConcurrentCopies, PeakInFlight, Reserved;
    ULONGLONG IdleSweeps, IdleExpired, NoticeSequence, NoticeLost;
    ULONG NoticeQueued, WorkerRunning;
    ULONG PublicationInFlight, StopCompleted, TestPauseEntered, TestPauseTimedOut;
} ST_HEALTH;
C_ASSERT(sizeof(ST_HEALTH)==224);
C_ASSERT(FIELD_OFFSET(ST_HEALTH,MaxConcurrentCopies)==156);
C_ASSERT(FIELD_OFFSET(ST_HEALTH,PeakInFlight)==160);
static KSPIN_LOCK StLock;
static EX_RUNDOWN_REF StRundown;
static EX_RUNDOWN_REF StPublicationRundown;
static ST_ENTRY StEntries[ST_SLOTS];
static volatile LONG StEnabled, StInFlight, StStopping;
static volatile LONG StFullCopies;
static ULONG StFullCopiesPeak;
static ULONGLONG StHeaderRefusals,StFullCopyRefusals;
typedef struct _ST_ADMISSION_HEALTH {
    ULONG Version,Size,MaxQualification,MaxFullCopies,QualificationInFlight,FullCopiesInFlight,QualificationPeak,FullCopiesPeak;
    ULONGLONG QualificationRefusals,FullCopyRefusals;
} ST_ADMISSION_HEALTH;
C_ASSERT(sizeof(ST_ADMISSION_HEALTH)==48);
static volatile LONG64 StBytes;
static ULONGLONG StNextId;
static ST_HEALTH StHealth;
static ST_NOTICE StNotices[ST_NOTICE_CAPACITY];
static ULONG StNoticeRead,StNoticeWrite;
static KEVENT StWorkerStop;
static HANDLE StWorkerHandle;
static volatile LONG StWorkerReady;
static KEVENT StStopComplete,StTestPublicationGate;
static volatile LONG StStopInitiated,StStopFinished,StPublicationInFlight,StTestPauseArmed,StTestPauseEntered,StTestPauseTimedOut;
#include "ReadyPublicationDiagnostic.h"
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
#include "NegativeAcquisitionAssociation.h"
#define SQ_GET_ACQUISITION_ORDERING 43u
#define SQ_GET_EXACT_ACQUISITION_ORDERING 44u
typedef struct _ST_ORDERING_REQUEST {
    ULONG Version,Command;
    UUID Provider;
    ULONGLONG Epoch,Candidate,Generation,Pid,Created;
} ST_ORDERING_REQUEST;
C_ASSERT(sizeof(ST_ORDERING_REQUEST)==64);
typedef struct _ST_ORDERING_HEALTH {
    ULONG Version,Size;
    UUID Provider;
    ULONGLONG Epoch,Binds,PendingBinds,ReadyBinds,Candidate,Generation,Pid,Created,BeginQpc,BindQpc,TerminalQpc;
    ULONG Phase,Active;
    ULONGLONG Reserved;
} ST_ORDERING_HEALTH;
C_ASSERT(sizeof(ST_ORDERING_HEALTH)==128);
static ST_ORDERING_HEALTH StOrdering;
// Passive instrumentation only: no pause, wait, synthetic callback or bind.
static VOID StSetPostPhase(ULONGLONG id,ULONG phase)
{
    ULONG i;KIRQL old;if(!id)return;
    KeAcquireSpinLock(&StLock,&old);
    for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File&&StEntries[i].Id==id){
        if(phase==6&&StEntries[i].PostPhase==6)break;
        StEntries[i].PostPhase=phase;
        if(phase==6){StEntries[i].PostActive=0;StEntries[i].PostTerminalQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
            if(StOrdering.Candidate==id)StOrdering.TerminalQpc=StEntries[i].PostTerminalQpc;}
        break;
    }
    KeReleaseSpinLock(&StLock,old);
}
#endif
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
#include "AcquisitionFaultQualification.h"
#endif
// StLock is held. No pointers/handles or guessed opener-as-actor identities leave the driver.
static VOID StNotice(ULONG kind,ULONG reason,NTSTATUS status,const ST_ENTRY* entry)
{
    ST_NOTICE row={0};row.Version=1;row.Size=sizeof(row);row.Kind=kind;row.Reason=reason;row.Status=(ULONG)status;
    row.Sequence=++StHealth.NoticeSequence;row.Monotonic=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&row.ObservedUtc);row.EmissionIrql=KeGetCurrentIrql();
    if(entry){row.Flags=1|4|8|16;row.Id=entry->Id;row.FileId=entry->FileId;row.Length=entry->Length;
        row.OriginalAccess=entry->OriginalRequestedAccess;row.MappedAccess=entry->MappedRequestedAccess;
        row.QualificationVersion=entry->QualificationVersion;row.CreateStatus=entry->CreateStatus;
        if(entry->Pid){row.Flags|=2;row.Pid=entry->Pid;row.Created=entry->Created;}}
    if(StHealth.NoticeQueued==ST_NOTICE_CAPACITY){StHealth.NoticeLost++;return;}
    StNotices[StNoticeWrite]=row;StNoticeWrite=(StNoticeWrite+1)%ST_NOTICE_CAPACITY;StHealth.NoticeQueued++;
}
static BOOLEAN StAcquire(VOID)
{
    if(InterlockedCompareExchange(&StStopping,0,0)||!ExAcquireRundownProtection(&StRundown))return FALSE;
    if(InterlockedCompareExchange(&StStopping,0,0)){ExReleaseRundownProtection(&StRundown);return FALSE;}
    return TRUE;
}
// Laboratory aggregate diagnostics: 1 context, 2 no read access, 3 unsupported
// file, 4 metadata/size, 5 capacity, 6 allocation, 7 read, 8 changed, 9 deadline,
// 10 candidate lost. These do not replace per-event production error evidence.
static VOID StFailure(NTSTATUS status,ULONG reason,BOOLEAN skipped)
{
    KIRQL old;KeAcquireSpinLock(&StLock,&old);
    if(skipped)StHealth.Skipped++;else StHealth.ReadFailures++;
    StHealth.LastStatus=(ULONG)status;StHealth.LastReason=reason;
    StNotice(skipped?11:12,reason,status,NULL);
    KeReleaseSpinLock(&StLock,old);
}

static VOID StRelease(ST_BLOB* blob)
{
    if(blob&&InterlockedDecrement(&blob->References)==0){
        RtlSecureZeroMemory(blob->Bytes,blob->Length);ExFreePoolWithTag(blob->Bytes,ST_TAG);
        InterlockedExchangeAdd64(&StBytes,-(LONG64)blob->Length);
        PmRelease(blob->ProcessMetadata);ExFreePoolWithTag(blob,ST_TAG);
    }
}
static NTSTATUS StDurableAck(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    ST_DURABLE_ACK claim;ULONG i,slot=ST_ACK_CAPACITY;KIRQL old;ULONGLONG now;
    ST_BLOB* blob=NULL;PFILE_OBJECT file=NULL;PM_OBJECT* metadata=NULL;NTSTATUS status=STATUS_NOT_FOUND;
    if(inputBytes!=sizeof(claim)||!output||outputBytes<sizeof(claim))return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&claim,input,sizeof(claim));
    if(claim.Key.Version!=4||claim.Key.Command!=21||claim.Key.Schema!=2||claim.ClaimVersion!=1||claim.Key.Operation!=11||claim.Key.Offset||claim.Key.Length||
        !claim.Key.Generation||!claim.Key.Id||!claim.Key.Pid||!claim.Key.Created||!claim.ByteLength||claim.ByteLength>ST_MAX_IMAGE)return STATUS_INVALID_PARAMETER;
    if(!RtlEqualMemory(&claim.Key.Provider,&SbHealth.Provider,sizeof(UUID)))return STATUS_NOT_FOUND;
    now=KeQueryInterruptTime();KeAcquireSpinLock(&StLock,&old);
    for(i=0;i<ST_ACK_CAPACITY;i++){
        ST_ACK_ENTRY* saved=&StAcknowledgements[i];
        if(saved->Deadline<=now){if(slot==ST_ACK_CAPACITY)slot=i;continue;}
        if(saved->Claim.Key.Generation==claim.Key.Generation&&saved->Claim.Key.Id==claim.Key.Id&&saved->Claim.Key.Pid==claim.Key.Pid&&saved->Claim.Key.Created==claim.Key.Created){
            status=RtlEqualMemory(&saved->Claim,&claim,sizeof(claim))?STATUS_SUCCESS:STATUS_DATA_ERROR;
            if(!NT_SUCCESS(status))StNotice(16,24,status,NULL);
            goto Unlock;
        }
    }
    if(slot==ST_ACK_CAPACITY){status=STATUS_INSUFFICIENT_RESOURCES;StNotice(16,25,status,NULL);goto Unlock;}
    for(i=0;i<ST_SLOTS;i++){
        ST_ENTRY* entry=&StEntries[i];
        if(!entry->Blob||entry->ProcessGeneration!=claim.Key.Generation||entry->Id!=claim.Key.Id||entry->Pid!=claim.Key.Pid||entry->Created!=claim.Key.Created)continue;
        if(entry->Blob->Length!=claim.ByteLength){status=STATUS_DATA_ERROR;StNotice(16,26,status,entry);break;}
        StAcknowledgements[slot].Claim=claim;StAcknowledgements[slot].Deadline=now+ST_ACK_TTL;
        // Transfers and operation companions hold independent blob references.
        // Detachment cannot release their bytes or recycle their identity.
        blob=entry->Blob;file=entry->File;metadata=entry->ProcessMetadata;StNotice(5,27,STATUS_SUCCESS,entry);RtlZeroMemory(entry,sizeof(*entry));
        StHealth.Live--;StHealth.Released++;StHealth.Acks++;status=STATUS_SUCCESS;break;
    }
Unlock:
    KeReleaseSpinLock(&StLock,old);
    if(file)ObDereferenceObjectDeferDelete(file);if(blob)StRelease(blob);PmRelease(metadata);
    if(NT_SUCCESS(status)){RtlCopyMemory(output,&claim,sizeof(claim));*returned=sizeof(claim);}
    return status;
}
static ST_BLOB* StObserveBinding(PEPROCESS process,ULONGLONG instance,ULONGLONG sequence,SB_BINDING* binding,SQ_ACQUISITION_OUTCOME* outcome)
{
    ST_BLOB* held=NULL;ULONG i;KIRQL old,registryOld;
#ifndef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    UNREFERENCED_PARAMETER(outcome);
#else
    if(outcome){RtlZeroMemory(outcome,sizeof(*outcome));outcome->Version=1;outcome->Size=sizeof(*outcome);
        outcome->Epoch=instance;outcome->Instance=instance;outcome->Sequence=sequence;
        outcome->ObservedQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;outcome->NativeStatus=STATUS_NOT_FOUND;}
#endif
    // Lock order is always staging then registry. The reference is taken while
    // the live process mapping and ready candidate are both protected.
    KeAcquireSpinLock(&StLock,&old);SbObserve(process,instance,sequence,binding);
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    if(outcome)SbAcquisitionObserve(process,outcome);
#endif
    // This branch touches only resident scalar registries and an immutable
    // NonPagedPoolNx blob. No token query, allocation, I/O or wait occurs here.
    // Enable APC entry only in the explicit qualification build until accepted.
#ifdef SQ_APC_PIN_DIAGNOSTIC
    if(old<=APC_LEVEL&&StEnabled&&binding->Flags==1)for(i=0;i<ST_SLOTS;i++){
#else
    if(old==PASSIVE_LEVEL&&StEnabled&&binding->Flags==1)for(i=0;i<ST_SLOTS;i++){
#endif
        ST_ENTRY* e=&StEntries[i];
        if(e->Id==binding->Candidate&&e->ProcessGeneration==binding->Generation&&e->Blob&&e->Deadline>KeQueryInterruptTime()){
            held=e->Blob;InterlockedIncrement(&held->References);
            KeAcquireSpinLock(&SbLock,&registryOld);SbHealth.OperationPins++;KeReleaseSpinLock(&SbLock,registryOld);break;
        }
    }
    if(!held){binding->Flags=StEnabled&&binding->Flags==1?2:0;binding->Status=(ULONG)STATUS_NOT_FOUND;
        if(binding->Reason==0){
#ifdef SQ_APC_PIN_DIAGNOSTIC
            binding->Reason=old<=APC_LEVEL?4:5;
#else
            binding->Reason=old==PASSIVE_LEVEL?4:5;
#endif
        }
        // Version 2 can retain an exact live-process generation after bounded
        // byte expiry/ACK. Only a consumer with that full key already durably
        // acquired may reuse its copy; no PID/path lookup is implied.
        if(!binding->Flags)binding->Generation=binding->Candidate=binding->Pid=binding->Created=0;}
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    if(outcome&&outcome->ProcessGeneration&&outcome->State==SQ_ACQ_BYTES_UNAVAILABLE){
        if(held){outcome->State=SQ_ACQ_BLOB_PINNED;outcome->NativeStatus=STATUS_SUCCESS;outcome->Certainty=2;}
        else if(StEnabled)for(i=0;i<ST_SLOTS;i++){
            const ST_ENTRY* e=&StEntries[i];
            if(e->Id==outcome->OriginCandidate&&e->ProcessGeneration==outcome->ProcessGeneration&&e->File&&!e->Blob&&e->Deadline>KeQueryInterruptTime()){
                outcome->State=SQ_ACQ_COPY_PENDING;outcome->NativeStatus=STATUS_PENDING;break;
            }
        }
    }
#endif
    KeReleaseSpinLock(&StLock,old);return held;
}
static VOID StReleaseOperation(ST_BLOB* held)
{
    KIRQL old;if(!held)return;
    StRelease(held);KeAcquireSpinLock(&SbLock,&old);SbHealth.OperationPinsReleased++;KeReleaseSpinLock(&SbLock,old);
}
// Reclaim completed, unbound candidates before refusing byte credit. A bound
// process generation or an unfinished read is never an eviction victim. Credit
// and detachment are serialized; dereference/free always happen outside StLock.
static BOOLEAN StReserveBytes(ULONG length)
{
    ULONG attempts,i,slot;KIRQL old;ULONGLONG oldest;BOOLEAN credit;
    for(attempts=0;attempts<=ST_SLOTS;attempts++){
        ST_ENTRY evicted={0};credit=FALSE;slot=ST_SLOTS;oldest=MAXULONGLONG;
        KeAcquireSpinLock(&StLock,&old);
        if(StEnabled){
            if((ULONGLONG)InterlockedCompareExchange64(&StBytes,0,0)+length<=ST_MAX_BYTES){
                LONG64 now=InterlockedExchangeAdd64(&StBytes,length)+length;credit=TRUE;
                if((ULONGLONG)now>StHealth.PeakBytes)StHealth.PeakBytes=(ULONGLONG)now;
            }else if(attempts<ST_SLOTS){
                for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File&&!StEntries[i].Pid&&StEntries[i].Blob&&StEntries[i].Id<oldest){oldest=StEntries[i].Id;slot=i;}
                if(slot!=ST_SLOTS){
                    evicted=StEntries[slot];StNotice(8,18,STATUS_SUCCESS,&StEntries[slot]);
                    RtlZeroMemory(&StEntries[slot],sizeof(ST_ENTRY));StHealth.Live--;StHealth.Released++;StHealth.UnboundEvictions++;
                }
            }
        }
        KeReleaseSpinLock(&StLock,old);
        if(credit)return TRUE;
        if(!evicted.File)return FALSE;
        ObDereferenceObjectDeferDelete(evicted.File);StRelease(evicted.Blob);PmRelease(evicted.ProcessMetadata);
    }
    return FALSE;
}
static VOID StSweepCore(BOOLEAN all,PFILE_OBJECT cleanup,BOOLEAN idle)
{
    ULONG i;KIRQL old;ULONGLONG now=KeQueryInterruptTime();
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    StNegativeSweep(all,cleanup);
#endif
    // One detached local entry keeps kernel stack use bounded as metadata grows.
    for(i=0;i<ST_SLOTS;i++){
        ST_ENTRY release={0};
        KeAcquireSpinLock(&StLock,&old);
        if(StEntries[i].File&&(all||(cleanup?(StEntries[i].File==cleanup&&!StEntries[i].Pid):StEntries[i].Deadline<=now))){
            release=StEntries[i];
            if(!all&&!cleanup){StHealth.Expired++;if(idle)StHealth.IdleExpired++;}
            StNotice(all?9:cleanup?7:6,idle?1:0,STATUS_SUCCESS,&StEntries[i]);
            RtlZeroMemory(&StEntries[i],sizeof(ST_ENTRY));StHealth.Live--;StHealth.Released++;
        }
        KeReleaseSpinLock(&StLock,old);
        if(release.File){ObDereferenceObjectDeferDelete(release.File);StRelease(release.Blob);PmRelease(release.ProcessMetadata);}
    }
}
static VOID StSweep(BOOLEAN all,PFILE_OBJECT cleanup)
{
    if(!StAcquire())return;
    __try{StSweepCore(all,cleanup,FALSE);}__finally{ExReleaseRundownProtection(&StRundown);}
}
static VOID StDisable(VOID)
{
    KIRQL old;
    if(!StAcquire())return;
    __try{
        if(InterlockedCompareExchange(&StStopInitiated,1,0)==0){
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
            CfStop();
#endif
            KeAcquireSpinLock(&StLock,&old);InterlockedExchange(&StEnabled,0);KeReleaseSpinLock(&StLock,old);
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
            AfClear();
#endif
            // This one-way rundown covers only publication, never generated file I/O.
            ExWaitForRundownProtectionRelease(&StPublicationRundown);
            SbStop();StSweepCore(TRUE,NULL,FALSE);InterlockedExchange(&StStopFinished,1);
            KeAcquireSpinLock(&StLock,&old);StNotice(15,0,STATUS_SUCCESS,NULL);KeReleaseSpinLock(&StLock,old);
            KeSetEvent(&StStopComplete,IO_NO_INCREMENT,FALSE);
        }else KeWaitForSingleObject(&StStopComplete,Executive,KernelMode,FALSE,NULL);
    }__finally{ExReleaseRundownProtection(&StRundown);}
}
static VOID StExpiryWorker(PVOID context)
{
    LARGE_INTEGER interval;KIRQL old;NTSTATUS status;UNREFERENCED_PARAMETER(context);interval.QuadPart=-10000000LL;
    KeAcquireSpinLock(&StLock,&old);StHealth.WorkerRunning=1;KeReleaseSpinLock(&StLock,old);
    for(;;){
        status=KeWaitForSingleObject(&StWorkerStop,Executive,KernelMode,FALSE,&interval);
        if(status!=STATUS_TIMEOUT)break;
        if(!StAcquire())break;
        __try{if(InterlockedCompareExchange(&StEnabled,0,0)){
            StSweepCore(FALSE,NULL,TRUE);
            KeAcquireSpinLock(&StLock,&old);StHealth.IdleSweeps++;KeReleaseSpinLock(&StLock,old);
        }}__finally{ExReleaseRundownProtection(&StRundown);}
    }
    KeAcquireSpinLock(&StLock,&old);StHealth.WorkerRunning=0;KeReleaseSpinLock(&StLock,old);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
static NTSTATUS StStartWorker(VOID)
{
    OBJECT_ATTRIBUTES attributes;NTSTATUS status;
    InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
    status=PsCreateSystemThread(&StWorkerHandle,SYNCHRONIZE,&attributes,NULL,NULL,StExpiryWorker,NULL);
    if(NT_SUCCESS(status))InterlockedExchange(&StWorkerReady,1);
    return status;
}
static NTSTATUS StQuiesce(VOID)
{
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    CfStop();
#endif
    InterlockedExchange(&StStopping,1);InterlockedExchange(&StEnabled,0);
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    AfClear();
#endif
    InterlockedExchange(&StWorkerReady,0);KeSetEvent(&StWorkerStop,IO_NO_INCREMENT,FALSE);
    if(StWorkerHandle){NTSTATUS status=ZwWaitForSingleObject(StWorkerHandle,FALSE,NULL);
        if(status!=STATUS_SUCCESS)return status;
        ZwClose(StWorkerHandle);StWorkerHandle=NULL;}
    return STATUS_SUCCESS;
}
// Invoked after Filter Manager and process/image callback roots have been removed.
// The static stopping/rundown gate remains allocated throughout root removal.
static VOID StFinishShutdown(VOID)
{
    // A blocked generated read can delay this wait. Never force-unload its code.
    ExWaitForRundownProtectionRelease(&StRundown);SbStop();StSweepCore(TRUE,NULL,FALSE);
}
static VOID StProcessCore(PEPROCESS process,HANDLE pid,PPS_CREATE_NOTIFY_INFO info)
{
    ULONG i,metadataState=0;KIRQL old;ULONGLONG candidate=0,created=(ULONGLONG)PsGetProcessCreateTimeQuadPart(process);PM_OBJECT* metadata=NULL;
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    CF_SELECTION selection={0};ULONGLONG faultGeneration=0;BOOLEAN faultAttached=FALSE;
#endif
    if(!InterlockedCompareExchange(&StEnabled,0,0))return;
    if(info){
        if(!NT_SUCCESS(info->CreationStatus)||!info->FileObject)return;
        // Copy only a scalar candidate key while holding the lock. FileObject
        // remains callback-owned. Never retain an entry pointer across unlock.
        KeAcquireSpinLock(&StLock,&old);
        if(StEnabled)for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File==info->FileObject&&!StEntries[i].Pid){candidate=StEntries[i].Id;break;}
        KeReleaseSpinLock(&StLock,old);
        if(!candidate){
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            StNegativeBind(process,pid,created,info);
#endif
            return;
        }
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
        selection=CfSelect(info,candidate,pid,created);
        metadata=PmCapture(info,&metadataState,selection.Mode);
#else
        metadata=PmCapture(info,&metadataState);
#endif
    }
    KeAcquireSpinLock(&StLock,&old);
    if(StEnabled)for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File){
        ST_ENTRY* entry=&StEntries[i];
        if(info&&entry->Id==candidate&&entry->File==info->FileObject&&!entry->Pid){
            // Expiry/STOP may detach the candidate during capture. Full-key
            // revalidation prevents publication onto a reused slot.
            entry->Pid=(ULONGLONG)pid;entry->Created=created;StHealth.Matched++;
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
            entry->ProcessGeneration=selection.Mode==CF_BIND_FAILURE?0:SbBind(process,pid,created,entry->Id);
            faultAttached=TRUE;faultGeneration=entry->ProcessGeneration;
#else
            entry->ProcessGeneration=SbBind(process,pid,created,entry->Id);
#endif
            // A failed binding retains PID/start only as failed lifecycle data;
            // it cannot be rebound, queried with a strong key, readied or ACKed.
            if(!entry->ProcessGeneration){StNotice(10,32,STATUS_UNSUCCESSFUL,entry);break;}
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            StOrdering.Binds++;
            if(entry->PostActive&&entry->PostPhase!=6)StOrdering.PendingBinds++;else StOrdering.ReadyBinds++;
            StOrdering.Candidate=entry->Id;StOrdering.Generation=entry->ProcessGeneration;StOrdering.Pid=entry->Pid;StOrdering.Created=entry->Created;
            StOrdering.BeginQpc=entry->PostBeginQpc;StOrdering.TerminalQpc=entry->PostTerminalQpc;StOrdering.BindQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
            StOrdering.Phase=entry->PostPhase;StOrdering.Active=entry->PostActive;
            entry->BindPhase=entry->PostPhase;entry->BindActive=entry->PostActive;entry->BindQpc=StOrdering.BindQpc;
#endif
            entry->ProcessMetadata=metadata;entry->ProcessMetadataState=metadataState;metadata=NULL;
            if(entry->Blob){entry->Blob->ProcessMetadata=entry->ProcessMetadata;entry->Blob->ProcessMetadataState=metadataState;PmReference(entry->ProcessMetadata);}
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            if(entry->Blob)SbAcquisitionSet(entry->ProcessGeneration,SQ_ACQ_BYTES_UNAVAILABLE,SQ_ACQ_STAGE_NONE,STATUS_NOT_FOUND,0,entry->Id,0);
#endif
            StNotice(3,0,STATUS_SUCCESS,entry);
            if(entry->Blob&&!entry->Counted){entry->Counted=TRUE;StHealth.BoundBuffersReady++;}
            StReadyPublish(entry);break;
        }else if(!info&&entry->Pid==(ULONGLONG)pid&&entry->Created==created){entry->Exited=TRUE;StNotice(4,0,STATUS_SUCCESS,entry);}
    }
    KeReleaseSpinLock(&StLock,old);PmRelease(metadata);
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    CfFinish(selection,metadataState,faultGeneration,faultAttached);
#endif
    if(!info)SbExit(process);
}
static BOOLEAN StQualifyPreCreate(PFLT_CALLBACK_DATA data,PULONG mappedRequestedAccess)
{
    PFLT_FILE_NAME_INFORMATION name=NULL;NTSTATUS status=STATUS_INVALID_DEVICE_STATE;BOOLEAN qualified=FALSE;ULONG reason=12;KIRQL old;ACCESS_MASK requested=0;
    *mappedRequestedAccess=0;
    if(!StAcquire())return FALSE;
    __try{
        if(!StEnabled||KeGetCurrentIrql()!=PASSIVE_LEVEL||KeAreAllApcsDisabled()||IoGetTopLevelIrp())__leave;
        if(FlagOn(data->Iopb->OperationFlags,SL_OPEN_TARGET_DIRECTORY)){status=STATUS_NOT_SUPPORTED;reason=15;__leave;}
        if(!data->Iopb->Parameters.Create.SecurityContext)__leave;
        requested=data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        RtlMapGenericMask(&requested,IoGetFileObjectGenericMapping());*mappedRequestedAccess=requested;
        KeAcquireSpinLock(&StLock,&old);StHealth.LastMappedRequestedAccess=requested;KeReleaseSpinLock(&StLock,old);
        if(!SqExecutableMappedAccess(requested)){status=STATUS_NOT_SUPPORTED;reason=16;__leave;}
        // Windows 8.1/2012 R2 require pre-CREATE to distinguish metadata streams.
        status=FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_DEFAULT,&name);
        if(!NT_SUCCESS(status))__leave;
        status=FltParseFileNameInformation(name);
        if(NT_SUCCESS(status)&&!name->Stream.Length&&name->FinalComponent.Length)qualified=TRUE;
        else if(NT_SUCCESS(status))status=STATUS_NOT_SUPPORTED;
    }__finally{if(name)FltReleaseFileNameInformation(name);if(!qualified)StFailure(status,reason,TRUE);ExReleaseRundownProtection(&StRundown);}
    return qualified;
}
static VOID StPostCreateCore(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,FLT_POST_OPERATION_FLAGS flags,BOOLEAN preQualified,ULONG mappedRequestedAccess,ULONG originalRequestedAccess)
{
    FILE_STANDARD_INFORMATION before={0},after={0};FILE_BASIC_INFORMATION basic={0},last={0};FILE_INTERNAL_INFORMATION identity={0};
    ST_BLOB* blob=NULL;PFILE_OBJECT file=objects->FileObject,release=NULL;LARGE_INTEGER offset;ULONG read=0,total=0,i,length=0,calls=0,reason=4,slot=ST_SLOTS;KIRQL old;
    ST_ENTRY evicted={0};
    NTSTATUS status=STATUS_UNSUCCESSFUL;BOOLEAN credit=FALSE,referenced=FALSE,kept=FALSE,notPrimary=FALSE,fullCopySlot=FALSE;LONG active;
    UCHAR dos[64],pe[24];unsigned int peOffset=0;int imageKind;
    PFLT_FILE_NAME_INFORMATION name=NULL;
    ULONGLONG id=0,deadline=KeQueryInterruptTime()+5ULL*10000000ULL;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    ULONG acquisitionFlags=0;
#endif
    if(!preQualified||!InterlockedCompareExchange(&StEnabled,0,0)||data->Iopb->MajorFunction!=IRP_MJ_CREATE||
        !data->Iopb->Parameters.Create.SecurityContext||
        !SqExecutableMappedAccess(mappedRequestedAccess)||
        FlagOn(flags,FLTFL_POST_OPERATION_DRAINING)||!NT_SUCCESS(data->IoStatus.Status)||data->IoStatus.Status==STATUS_REPARSE||!file)return;
    if(data->IoStatus.Status==STATUS_OPLOCK_BREAK_IN_PROGRESS){StFailure(data->IoStatus.Status,14,TRUE);return;}
    // Unsupported candidates are not opened by name or with elevated replacement rights.
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL||KeAreAllApcsDisabled()||IoGetTopLevelIrp()||objects->Transaction){StFailure(STATUS_INVALID_DEVICE_STATE,1,TRUE);return;}
    if(!file->ReadAccess){StFailure(STATUS_ACCESS_DENIED,2,TRUE);return;}
    if(FlagOn(file->Flags,FO_CLEANUP_COMPLETE|FO_NO_INTERMEDIATE_BUFFERING|FO_STREAM_FILE)||
        FlagOn(data->Iopb->Parameters.Create.Options,FILE_DIRECTORY_FILE)||FsRtlIsPagingFile(file)){StFailure(STATUS_NOT_SUPPORTED,3,TRUE);return;}
    // FILE_OBJECT.FileName is not valid after CREATE starts processing. Obtain
    // a Filter Manager-owned name and parse the stream component instead.
    status=FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_DEFAULT,&name);
    if(!NT_SUCCESS(status)){StFailure(status,11,TRUE);return;}
    status=FltParseFileNameInformation(name);
    if(NT_SUCCESS(status)&&(name->Stream.Length||!name->FinalComponent.Length))status=STATUS_NOT_SUPPORTED;
    FltReleaseFileNameInformation(name);name=NULL;
    if(!NT_SUCCESS(status)){StFailure(status,11,TRUE);return;}
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_HEADER,&status,&acquisitionFlags)){
        StNegativeAddFlags(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_HEADER,status,acquisitionFlags);StFailure(status,19,TRUE);return;
    }
#endif
    active=InterlockedIncrement(&StInFlight);
    if(active>ST_MAX_INFLIGHT){InterlockedDecrement(&StInFlight);KeAcquireSpinLock(&StLock,&old);StHealth.PoolDrops++;if(StHeaderRefusals!=MAXULONGLONG)StHeaderRefusals++;KeReleaseSpinLock(&StLock,old);
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        StNegativeAdd(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_HEADER,STATUS_INSUFFICIENT_RESOURCES);
#endif
        StFailure(STATUS_INSUFFICIENT_RESOURCES,19,TRUE);return;}
    KeAcquireSpinLock(&StLock,&old);StHealth.Reads++;
    StHealth.PeakInFlight=max(StHealth.PeakInFlight,(ULONG)active);KeReleaseSpinLock(&StLock,old);
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(!AfConsume(SQ_ACQ_STAGE_SOURCE_STANDARD,&status,&acquisitionFlags))
#endif
    status=FltQueryInformationFile(objects->Instance,file,&before,sizeof(before),FileStandardInformation,NULL);
    if(!NT_SUCCESS(status)){
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        StNegativeAddFlags(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_SOURCE_STANDARD,status,acquisitionFlags);
#endif
        goto Done;
    }
    if(before.Directory||before.EndOfFile.QuadPart<=0||before.EndOfFile.QuadPart>ST_MAX_IMAGE){status=STATUS_NOT_SUPPORTED;goto Done;}
    length=(ULONG)before.EndOfFile.QuadPart;
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(!AfConsume(SQ_ACQ_STAGE_SOURCE_BASIC,&status,&acquisitionFlags))
#endif
    status=FltQueryInformationFile(objects->Instance,file,&basic,sizeof(basic),FileBasicInformation,NULL);
    if(!NT_SUCCESS(status)){
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        StNegativeAddFlags(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_SOURCE_BASIC,status,acquisitionFlags);
#endif
        goto Done;
    }
    if(FlagOn(basic.FileAttributes,FILE_ATTRIBUTE_REPARSE_POINT)){status=STATUS_NOT_SUPPORTED;goto Done;}
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(!AfConsume(SQ_ACQ_STAGE_SOURCE_INTERNAL,&status,&acquisitionFlags))
#endif
    status=FltQueryInformationFile(objects->Instance,file,&identity,sizeof(identity),FileInternalInformation,NULL);
    if(!NT_SUCCESS(status)){
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        StNegativeAddFlags(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_SOURCE_INTERNAL,status,acquisitionFlags);
#endif
        goto Done;
    }
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_METADATA,&status,&acquisitionFlags)){reason=18;goto Done;}
#endif
    status=ObReferenceObjectByPointer(file,0,*IoFileObjectType,KernelMode);if(!NT_SUCCESS(status))goto Done;referenced=TRUE;
    // Internal provisional entry precedes all reads. It can bind during copying,
    // but cannot be retrieved until its completed blob has been published.
    KeAcquireSpinLock(&StLock,&old);
    // A retained bound generation must not prevent a later process association
    // for the same executable file object. Only one unbound candidate is allowed.
    for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File==file&&!StEntries[i].Pid)break;
    if(i!=ST_SLOTS)StHealth.DuplicateDrops++;
    else if(StEnabled&&StNextId!=MAXULONGLONG){
        for(i=0;i<ST_SLOTS;i++)if(!StEntries[i].File){slot=i;break;}
        if(slot==ST_SLOTS){
            ULONGLONG oldest=MAXULONGLONG;
            // Discard only a completed, unbound provisional copy. An in-flight
            // copy or a bound process generation is never evicted for capacity.
            for(i=0;i<ST_SLOTS;i++)if(!StEntries[i].Pid&&StEntries[i].Blob&&StEntries[i].Id<oldest){oldest=StEntries[i].Id;slot=i;}
            if(slot!=ST_SLOTS){evicted=StEntries[slot];StNotice(8,5,STATUS_SUCCESS,&StEntries[slot]);RtlZeroMemory(&StEntries[slot],sizeof(ST_ENTRY));StHealth.Live--;StHealth.Released++;StHealth.UnboundEvictions++;}
        }
    }
    if(slot!=ST_SLOTS){
        StEntries[slot].File=file;StEntries[slot].Id=id=++StNextId;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        StEntries[slot].PostActive=1;StEntries[slot].PostPhase=2;StEntries[slot].PostBeginQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
#endif
        StEntries[slot].Deadline=KeQueryInterruptTime()+30ULL*10000000ULL;
        StEntries[slot].FileId=(ULONGLONG)identity.IndexNumber.QuadPart;StEntries[slot].Length=length;
        StEntries[slot].OriginalRequestedAccess=originalRequestedAccess;StEntries[slot].MappedRequestedAccess=mappedRequestedAccess;
        StEntries[slot].QualificationVersion=2;StEntries[slot].CreateStatus=(ULONG)data->IoStatus.Status;
        StNotice(1,0,STATUS_SUCCESS,&StEntries[slot]);
        StHealth.Live++;StHealth.ProvisionalEntries++;referenced=FALSE;
    }
    else if(i==ST_SLOTS&&StEnabled&&StNextId!=MAXULONGLONG)StHealth.PoolDrops++;
    KeReleaseSpinLock(&StLock,old);
    if(evicted.File){ObDereferenceObjectDeferDelete(evicted.File);StRelease(evicted.Blob);PmRelease(evicted.ProcessMetadata);}
    if(!id){status=STATUS_DEVICE_BUSY;reason=5;goto Done;}
    // Avoid copying every executable-mapped DLL loaded by each process. PE DLLs
    // cannot be directly run; the primary actor still requires exact FILE_OBJECT
    // equality at process creation. Reads use this currently open, authorized FO.
    offset.QuadPart=0;read=0;reason=29;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    StSetPostPhase(id,3);
#endif
    status=FltReadFile(objects->Instance,file,&offset,sizeof(dos),dos,FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,&read,NULL,NULL);
    KeAcquireSpinLock(&StLock,&old);StHealth.ReadCalls++;KeReleaseSpinLock(&StLock,old);
    if(!NT_SUCCESS(status))goto Done;
    if(!SqPeOffset(dos,read,length,&peOffset)){status=STATUS_NOT_SUPPORTED;notPrimary=TRUE;goto Done;}
    offset.QuadPart=peOffset;read=0;
    status=FltReadFile(objects->Instance,file,&offset,sizeof(pe),pe,FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,&read,NULL,NULL);
    KeAcquireSpinLock(&StLock,&old);StHealth.ReadCalls++;KeReleaseSpinLock(&StLock,old);
    if(!NT_SUCCESS(status))goto Done;
    imageKind=SqPeKind(pe,read);
    if(imageKind!=1){status=STATUS_NOT_SUPPORTED;reason=imageKind==2?28:29;notPrimary=TRUE;goto Done;}
    // DLL/header qualification does not consume a full executable-copy slot.
    // Both gates refuse rather than waiting inside the caller's CREATE path.
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    StSetPostPhase(id,4);
#endif
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_FULL_COPY,&status,&acquisitionFlags)){reason=31;notPrimary=TRUE;goto Done;}
#endif
    active=InterlockedIncrement(&StFullCopies);
    if(active>ST_MAX_FULL_COPIES){
        InterlockedDecrement(&StFullCopies);KeAcquireSpinLock(&StLock,&old);
        StHealth.PoolDrops++;if(StFullCopyRefusals!=MAXULONGLONG)StFullCopyRefusals++;
        KeReleaseSpinLock(&StLock,old);status=STATUS_INSUFFICIENT_RESOURCES;reason=31;notPrimary=TRUE;goto Done;
    }
    fullCopySlot=TRUE;KeAcquireSpinLock(&StLock,&old);StFullCopiesPeak=max(StFullCopiesPeak,(ULONG)active);KeReleaseSpinLock(&StLock,old);
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_BYTE_CREDIT,&status,&acquisitionFlags)){reason=5;goto Done;}
#endif
    credit=StReserveBytes(length);
    if(!credit){
        KeAcquireSpinLock(&StLock,&old);if(StEnabled)StHealth.PoolDrops++;
        status=StEnabled?STATUS_INSUFFICIENT_RESOURCES:STATUS_CANCELLED;reason=StEnabled?5:17;
        KeReleaseSpinLock(&StLock,old);goto Done;
    }
    status=STATUS_INSUFFICIENT_RESOURCES;reason=6;
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_ALLOCATION,&status,&acquisitionFlags))goto Done;
#endif
#pragma warning(suppress:4996)
    blob=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*blob),ST_TAG);if(!blob)goto Done;
    RtlZeroMemory(blob,sizeof(*blob));blob->References=1;blob->Length=length;blob->RequestedAccess=mappedRequestedAccess;
    blob->OriginalRequestedAccess=originalRequestedAccess;blob->QualificationVersion=2;blob->CreateStatus=(ULONG)data->IoStatus.Status;
    SqReadVolumeIdentity(objects->Instance,&blob->SourceVolume);
#pragma warning(suppress:4996)
    blob->Bytes=ExAllocatePoolWithTag(NonPagedPoolNx,length,ST_TAG);if(!blob->Bytes){ExFreePoolWithTag(blob,ST_TAG);blob=NULL;goto Done;}
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&blob->CopyStartedUtc);
    reason=7;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    StSetPostPhase(id,5);
#endif
#ifdef SQ_ACQUISITION_FAULT_QUALIFICATION
    if(AfConsume(SQ_ACQ_STAGE_COPY_READ,&status,&acquisitionFlags))goto Done;
#endif
    while(total<length){
        ULONG chunk=min(ST_CHUNK,length-total);
        if(!InterlockedCompareExchange(&StEnabled,0,0)){status=STATUS_CANCELLED;reason=17;goto Done;}
        if(KeQueryInterruptTime()>deadline||++calls>256){status=STATUS_TIMEOUT;reason=9;goto Done;}
        offset.QuadPart=total;read=0;
        status=FltReadFile(objects->Instance,file,&offset,chunk,blob->Bytes+total,FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,&read,NULL,NULL);
        KeAcquireSpinLock(&StLock,&old);StHealth.ReadCalls++;KeReleaseSpinLock(&StLock,old);
        if(!NT_SUCCESS(status)||!read||read>chunk){status=NT_SUCCESS(status)?STATUS_DATA_ERROR:status;goto Done;}total+=read;
    }
    // Reject a header that changed between qualification and the retained copy.
    // This is an interval observation, not an atomic image-memory snapshot.
    if(!RtlEqualMemory(blob->Bytes,dos,sizeof(dos))||!RtlEqualMemory(blob->Bytes+peOffset,pe,sizeof(pe))){status=STATUS_RETRY;reason=30;goto Done;}
    status=FltQueryInformationFile(objects->Instance,file,&after,sizeof(after),FileStandardInformation,NULL);if(!NT_SUCCESS(status))goto Done;
    status=FltQueryInformationFile(objects->Instance,file,&last,sizeof(last),FileBasicInformation,NULL);if(!NT_SUCCESS(status))goto Done;
    if(after.Directory||after.EndOfFile.QuadPart!=before.EndOfFile.QuadPart||last.LastWriteTime.QuadPart!=basic.LastWriteTime.QuadPart||last.ChangeTime.QuadPart!=basic.ChangeTime.QuadPart){status=STATUS_RETRY;reason=8;goto Done;}
    if(!InterlockedCompareExchange(&StEnabled,0,0)){status=STATUS_CANCELLED;reason=17;goto Done;}
    if(KeQueryInterruptTime()>deadline){status=STATUS_TIMEOUT;reason=9;goto Done;}
    blob->FileId=(ULONGLONG)identity.IndexNumber.QuadPart;blob->CreatedUtc=basic.CreationTime.QuadPart;
    blob->ModifiedUtc=basic.LastWriteTime.QuadPart;blob->ChangedUtc=basic.ChangeTime.QuadPart;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&blob->CopyEndedUtc);
    if(!ExAcquireRundownProtection(&StPublicationRundown)){status=STATUS_CANCELLED;reason=17;goto Done;}
    __try{
        KeAcquireSpinLock(&StLock,&old);
        if(StEnabled)for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File==file&&StEntries[i].Id==id){
            blob->ProcessMetadata=StEntries[i].ProcessMetadata;blob->ProcessMetadataState=StEntries[i].ProcessMetadataState;PmReference(blob->ProcessMetadata);
            StEntries[i].Blob=blob;kept=TRUE;StEntries[i].Deadline=KeQueryInterruptTime()+30ULL*10000000ULL;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            StEntries[i].PostPhase=6;StEntries[i].PostActive=0;StEntries[i].PostTerminalQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
            if(StOrdering.Candidate==id)StOrdering.TerminalQpc=StEntries[i].PostTerminalQpc;
            if(StEntries[i].ProcessGeneration)SbAcquisitionSet(StEntries[i].ProcessGeneration,SQ_ACQ_BYTES_UNAVAILABLE,SQ_ACQ_STAGE_NONE,STATUS_NOT_FOUND,0,id,0);
#endif
            StNotice(2,0,STATUS_SUCCESS,&StEntries[i]);
            if(StEntries[i].Pid&&!StEntries[i].Counted){StEntries[i].Counted=TRUE;StHealth.BoundBuffersReady++;}
            StReadyPublish(&StEntries[i]);break;
        }
        // An entry detached by STOP, expiry or cleanup is not a capacity failure.
        KeReleaseSpinLock(&StLock,old);
    }__finally{ExReleaseRundownProtection(&StPublicationRundown);}
Done:
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    StSetPostPhase(id,6);
#endif
    if(!kept){
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        if(NT_SUCCESS(status)){status=STATUS_CANCELLED;reason=10;}
#endif
        if(id){
            PM_OBJECT* metadata=NULL;
            KeAcquireSpinLock(&StLock,&old);
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            if((!notPrimary||reason==31)&&!NT_SUCCESS(status)&&status!=STATUS_PENDING){
                ULONG failureStage=reason==31?SQ_ACQ_STAGE_FULL_COPY:reason==5?SQ_ACQ_STAGE_BYTE_CREDIT:reason==6?SQ_ACQ_STAGE_ALLOCATION:SQ_ACQ_STAGE_COPY_READ;
                SbAcquisitionFailCandidate(id,failureStage,status,acquisitionFlags);
            }
#endif
            for(i=0;i<ST_SLOTS;i++)if(StEntries[i].Id==id&&StEntries[i].File){
                ST_ENTRY* failed=&StEntries[i];release=failed->File;metadata=failed->ProcessMetadata;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
                if((!notPrimary||reason==31)&&!NT_SUCCESS(status)&&status!=STATUS_PENDING){
                    ULONG stage=reason==31?SQ_ACQ_STAGE_FULL_COPY:reason==5?SQ_ACQ_STAGE_BYTE_CREDIT:reason==6?SQ_ACQ_STAGE_ALLOCATION:SQ_ACQ_STAGE_COPY_READ;
                    if(failed->ProcessGeneration)SbAcquisitionSet(failed->ProcessGeneration,SQ_ACQ_BOUND_COPY_FAILURE,stage,status,0,id,acquisitionFlags);
                    else if(StNegativeStoreLocked(failed->File,id,SQ_ACQ_PREBIND_REFUSAL,stage,status,acquisitionFlags))release=NULL;
                }
#endif
                StNotice(10,reason,status,failed);RtlZeroMemory(failed,sizeof(ST_ENTRY));StHealth.Live--;StHealth.Released++;break;
            }
            KeReleaseSpinLock(&StLock,old);if(release)ObDereferenceObjectDeferDelete(release);PmRelease(metadata);
        }
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
        if(!id&&reason==18)StNegativeAddFlags(file,SQ_ACQ_PREBIND_REFUSAL,SQ_ACQ_STAGE_METADATA,status,acquisitionFlags);
#endif
        if(referenced)ObDereferenceObjectDeferDelete(file);
        if(blob)StRelease(blob);else if(credit)InterlockedExchangeAdd64(&StBytes,-(LONG64)length);
        if(NT_SUCCESS(status)){status=STATUS_CANCELLED;reason=10;}StFailure(status,reason,notPrimary);
    }
    if(fullCopySlot)InterlockedDecrement(&StFullCopies);
    InterlockedDecrement(&StInFlight);
}
// Existing diagnostic pause applies to each byte publication path, including
// an operation-owned pin. Call only after taking the blob/rundown references and
// releasing spin locks. This hook is absent from ordinary driver builds.
static NTSTATUS StPausePublication(VOID)
{
    if(InterlockedCompareExchange(&StTestPauseArmed,0,1)==1){
        LARGE_INTEGER timeout;NTSTATUS wait;timeout.QuadPart=-5LL*10000000LL;
        InterlockedExchange(&StTestPauseEntered,1);
        wait=KeWaitForSingleObject(&StTestPublicationGate,Executive,KernelMode,FALSE,&timeout);
        InterlockedExchange(&StTestPauseEntered,0);
        if(wait!=STATUS_SUCCESS){InterlockedIncrement(&StTestPauseTimedOut);return STATUS_IO_TIMEOUT;}
    }
    return STATUS_SUCCESS;
}
static NTSTATUS StMessageCore(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned,ULONGLONG instance)
{
    ST_REQUEST request={0};ST_REPLY reply={0};ST_BOUND_REQUEST bound={0};ST_BOUND_REPLY wide={0};ST_BLOB* blob=NULL;PFILE_OBJECT file=NULL;PM_OBJECT* metadata=NULL;ULONG i,replyBytes=sizeof(reply);KIRQL old;
    BOOLEAN strong=FALSE;
    ST_ENTRY publicationEvidence={0};NTSTATUS publicationStatus=STATUS_UNSUCCESSFUL;
    if(inputBytes<8)return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&request,input,min(inputBytes,sizeof(request)));
#ifdef SQ_APC_PIN_DIAGNOSTIC
    if(request.Command==36){
        // Synthetic IRQL-branch test only. It emits no file event and cannot
        // establish actual filesystem APC coverage or token capture. All port
        // buffers, process lookup and final releases are used at PASSIVE_LEVEL.
        struct {ULONG Version,Command;ULONGLONG Pid,Created;ULONG Iterations,Mode;} query;
        struct {ULONG Version,Size,EntryIrql,Attempts,Pins,Released;SB_BINDING Binding;} result={0};
        PEPROCESS actor=NULL;ULONG attempt;NTSTATUS lookup;
        C_ASSERT(sizeof(query)==32);C_ASSERT(sizeof(result)==112);
        if(inputBytes!=sizeof(query)||!output||outputBytes<sizeof(result)||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
        RtlCopyMemory(&query,input,sizeof(query));
        if(query.Version!=4||query.Iterations==0||query.Iterations>64||query.Mode>1)return STATUS_INVALID_PARAMETER;
        if(query.Mode==0){
            if(!query.Pid||!query.Created)return STATUS_INVALID_PARAMETER;
            lookup=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)query.Pid,&actor);
            if(!NT_SUCCESS(lookup))return lookup;
            if((ULONGLONG)PsGetProcessCreateTimeQuadPart(actor)!=query.Created){ObDereferenceObject(actor);return STATUS_NOT_FOUND;}
        }else if(query.Pid||query.Created)return STATUS_INVALID_PARAMETER;
        result.Version=1;result.Size=sizeof(result);result.EntryIrql=APC_LEVEL;
        for(attempt=0;attempt<query.Iterations;attempt++){
            SB_BINDING observed;ST_BLOB* pinned;KIRQL previous;
            KeRaiseIrql(APC_LEVEL,&previous);
            pinned=StObserveBinding(actor,0,0,&observed,NULL);
            KeLowerIrql(previous);
            result.Attempts++;result.Binding=observed;
            if(pinned){result.Pins++;StReleaseOperation(pinned);result.Released++;}
        }
        if(actor)ObDereferenceObject(actor);
        RtlCopyMemory(output,&result,sizeof(result));*returned=sizeof(result);return STATUS_SUCCESS;
    }
#endif
    if(request.Command==28){
        struct {ULONG Version,Size,Capacity,Live;ULONGLONG Allocated,Freed,Refused,Reserved;} health={0};
        C_ASSERT(sizeof(health)==48);
        if(inputBytes!=8||!output||outputBytes<sizeof(health))return STATUS_INVALID_PARAMETER;
        health.Version=1;health.Size=sizeof(health);health.Capacity=PM_CAPACITY;health.Live=(ULONG)InterlockedCompareExchange(&PmLive,0,0);
        health.Allocated=(ULONGLONG)InterlockedCompareExchange64(&PmAllocated,0,0);health.Freed=(ULONGLONG)InterlockedCompareExchange64(&PmFreed,0,0);health.Refused=(ULONGLONG)InterlockedCompareExchange64(&PmRefused,0,0);
        RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    if(request.Command==25)return StReadyPage(input,inputBytes,output,outputBytes,returned,instance);
    if(request.Command==21)return StDurableAck(input,inputBytes,output,outputBytes,returned);
    if(request.Command==24){
        ST_ADMISSION_HEALTH health={0};
        if(inputBytes!=8||!output||outputBytes<sizeof(health))return STATUS_INVALID_PARAMETER;
        health.Version=1;health.Size=sizeof(health);health.MaxQualification=ST_MAX_INFLIGHT;health.MaxFullCopies=ST_MAX_FULL_COPIES;
        health.QualificationInFlight=(ULONG)InterlockedCompareExchange(&StInFlight,0,0);health.FullCopiesInFlight=(ULONG)InterlockedCompareExchange(&StFullCopies,0,0);
        KeAcquireSpinLock(&StLock,&old);health.QualificationPeak=StHealth.PeakInFlight;health.FullCopiesPeak=StFullCopiesPeak;
        health.QualificationRefusals=StHeaderRefusals;health.FullCopyRefusals=StFullCopyRefusals;KeReleaseSpinLock(&StLock,old);
        RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    if(request.Command==20){
        SB_HEALTH health;
        if(inputBytes!=8||!output||outputBytes<sizeof(health))return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&SbLock,&old);health=SbHealth;KeReleaseSpinLock(&SbLock,old);
        RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    if(request.Command==19){
        if(inputBytes!=sizeof(bound))return STATUS_INVALID_PARAMETER;
        RtlCopyMemory(&bound,input,sizeof(bound));
        if(bound.Schema!=1||!bound.Generation||!bound.Id||!RtlEqualMemory(&bound.Provider,&SbHealth.Provider,sizeof(UUID)))return STATUS_NOT_FOUND;
        if(bound.Operation!=10&&bound.Operation!=11&&bound.Operation!=13&&bound.Operation!=26&&bound.Operation!=27)return STATUS_INVALID_PARAMETER;
        strong=TRUE;replyBytes=sizeof(wide);request.Command=bound.Operation;request.Id=bound.Id;request.Pid=bound.Pid;
        request.Created=bound.Created;request.Offset=bound.Offset;request.Length=bound.Length;
    }
    // Lab-only deterministic publication/STOP race control. The hold is bounded
    // to five seconds and is never taken on any file-operation callback path.
    if(request.Command==16||request.Command==17){
        if(inputBytes!=8)return STATUS_INVALID_PARAMETER;
        if(request.Command==17){KeSetEvent(&StTestPublicationGate,IO_NO_INCREMENT,FALSE);return STATUS_SUCCESS;}
        KeAcquireSpinLock(&StLock,&old);
        if(!StEnabled||StTestPauseArmed||StTestPauseEntered){KeReleaseSpinLock(&StLock,old);return STATUS_DEVICE_BUSY;}
        KeClearEvent(&StTestPublicationGate);InterlockedExchange(&StTestPauseArmed,1);KeReleaseSpinLock(&StLock,old);return STATUS_SUCCESS;
    }
    if(request.Command==15){
        ST_NOTICE row;BOOLEAN found=FALSE;
        if(inputBytes!=8||!output||outputBytes<sizeof(row))return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&StLock,&old);
        if(StHealth.NoticeQueued){row=StNotices[StNoticeRead];RtlZeroMemory(&StNotices[StNoticeRead],sizeof(row));
            StNoticeRead=(StNoticeRead+1)%ST_NOTICE_CAPACITY;StHealth.NoticeQueued--;found=TRUE;}
        KeReleaseSpinLock(&StLock,old);if(!found)return STATUS_NO_MORE_ENTRIES;
        RtlCopyMemory(output,&row,sizeof(row));*returned=sizeof(row);return STATUS_SUCCESS;
    }
    if(request.Command==14){
        ST_TABLE_VIEW* table;
        if(inputBytes!=8||!output||outputBytes<sizeof(*table))return STATUS_INVALID_PARAMETER;
#pragma warning(suppress:4996)
        table=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*table),ST_TAG);if(!table)return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(table,sizeof(*table));table->Version=3;table->Size=sizeof(*table);
        __try{
            KeAcquireSpinLock(&StLock,&old);
            for(i=0;i<ST_SLOTS;i++)if(StEntries[i].File){
                table->Slots[i].Id=StEntries[i].Id;table->Slots[i].Pid=StEntries[i].Pid;table->Slots[i].Created=StEntries[i].Created;
                table->Slots[i].Deadline=StEntries[i].Deadline;table->Slots[i].Ready=StEntries[i].Blob!=NULL;table->Slots[i].Exited=StEntries[i].Exited;
                if(StEntries[i].Blob){ST_BLOB* b=StEntries[i].Blob;table->Slots[i].FileId=b->FileId;
                    table->Slots[i].OriginalRequestedAccess=b->OriginalRequestedAccess;table->Slots[i].MappedRequestedAccess=b->RequestedAccess;
                    table->Slots[i].QualificationVersion=b->QualificationVersion;table->Slots[i].CreateStatus=b->CreateStatus;}
            }
            KeReleaseSpinLock(&StLock,old);RtlCopyMemory(output,table,sizeof(*table));*returned=sizeof(*table);
        }__finally{ExFreePoolWithTag(table,ST_TAG);}
        return STATUS_SUCCESS;
    }
    if(request.Command==12){
        ST_HEALTH health;
        if(inputBytes!=8||!output||outputBytes<sizeof(health))return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&StLock,&old);health=StHealth;KeReleaseSpinLock(&StLock,old);
        health.Version=3;health.Size=sizeof(health);health.Enabled=(ULONG)InterlockedCompareExchange(&StEnabled,0,0);
        health.MetadataSlots=ST_SLOTS;health.MaxConcurrentCopies=ST_MAX_INFLIGHT;
        health.InFlight=(ULONG)InterlockedCompareExchange(&StInFlight,0,0);health.Bytes=(ULONGLONG)InterlockedCompareExchange64(&StBytes,0,0);
        health.PublicationInFlight=(ULONG)InterlockedCompareExchange(&StPublicationInFlight,0,0);health.StopCompleted=(ULONG)InterlockedCompareExchange(&StStopFinished,0,0);
        health.TestPauseEntered=(ULONG)InterlockedCompareExchange(&StTestPauseEntered,0,0);health.TestPauseTimedOut=(ULONG)InterlockedCompareExchange(&StTestPauseTimedOut,0,0);
        RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    if((!strong&&inputBytes!=sizeof(request))||request.Length>ST_CHUNK||!request.Pid||!request.Created)return STATUS_INVALID_PARAMETER;
    if((request.Command==10||request.Command==13)&&(!output||outputBytes<replyBytes+request.Length))return STATUS_BUFFER_TOO_SMALL;
    if(request.Command!=10&&request.Command!=11&&request.Command!=13&&request.Command!=26&&request.Command!=27)return STATUS_INVALID_PARAMETER;
    if((request.Command==26||request.Command==27)&&(!strong||request.Offset||request.Length))return STATUS_INVALID_PARAMETER;
    if(request.Command==26&&(!output||outputBytes<sizeof(ST_SOURCE_IDENTITY_REPLY)))return STATUS_BUFFER_TOO_SMALL;
    if(request.Command==27&&(!output||outputBytes<sizeof(ST_PROCESS_METADATA_REPLY)))return STATUS_BUFFER_TOO_SMALL;
    if(request.Command==10&&!request.Id)return STATUS_INVALID_PARAMETER;
    // Discovery returns metadata only. Every byte read and ACK requires the ID.
    if(request.Command==13&&((!strong&&request.Id)||request.Offset||request.Length))return STATUS_INVALID_PARAMETER;
    if(request.Command==11&&(!request.Id||request.Offset||request.Length))return STATUS_INVALID_PARAMETER;
    if((request.Command==10||request.Command==13||request.Command==26||request.Command==27)&&!InterlockedCompareExchange(&StEnabled,0,0))return STATUS_DELETE_PENDING;
    KeAcquireSpinLock(&StLock,&old);
    for(i=0;i<ST_SLOTS;i++){
        ST_ENTRY* entry=&StEntries[i];
        if(!entry->Blob||entry->Pid!=request.Pid||entry->Created!=request.Created||(request.Id&&entry->Id!=request.Id)||(strong&&entry->ProcessGeneration!=bound.Generation))continue;
        if(request.Command==11){blob=entry->Blob;file=entry->File;metadata=entry->ProcessMetadata;StNotice(5,0,STATUS_SUCCESS,entry);RtlZeroMemory(entry,sizeof(*entry));StHealth.Live--;StHealth.Released++;StHealth.Acks++;break;}
        // Retrieval never extends TTL; only the passive expiry worker reaps expired bound entries.
        if(entry->Deadline<=KeQueryInterruptTime())continue;
        if(request.Offset>entry->Blob->Length)break;
        blob=entry->Blob;InterlockedIncrement(&blob->References);
        reply.Version=strong?3:2;reply.Size=replyBytes;reply.TotalBytes=blob->Length;reply.Offset=request.Offset;
        reply.Count=min(request.Length,blob->Length-request.Offset);reply.Flags=1u|4u|8u|(entry->Exited?2u:0u);
        reply.Reserved=blob->RequestedAccess; // Diagnostic v1 formerly reserved; explicit mapped pre-CREATE rights.
        reply.Id=entry->Id;reply.Pid=entry->Pid;reply.Created=entry->Created;reply.FileId=blob->FileId;
        reply.CreatedUtc=blob->CreatedUtc;reply.ModifiedUtc=blob->ModifiedUtc;reply.ChangedUtc=blob->ChangedUtc;
        reply.CopyStartedUtc=blob->CopyStartedUtc;reply.CopyEndedUtc=blob->CopyEndedUtc;
        reply.OriginalRequestedAccess=blob->OriginalRequestedAccess;reply.QualificationVersion=blob->QualificationVersion;reply.CreateStatus=blob->CreateStatus;
        if(request.Command==10&&reply.Count){publicationEvidence=*entry;StNotice(13,0,STATUS_SUCCESS,&publicationEvidence);}break;
    }
    KeReleaseSpinLock(&StLock,old);
    if(!blob)return STATUS_NOT_FOUND;
    if(request.Command==11){ObDereferenceObjectDeferDelete(file);StRelease(blob);PmRelease(metadata);return STATUS_SUCCESS;}
    __try{
        if(request.Command==27){StProcessMetadataReply(blob,&bound,0,0,output);*returned=sizeof(ST_PROCESS_METADATA_REPLY);return STATUS_SUCCESS;}
        if(request.Command==26){ST_SOURCE_IDENTITY_REPLY source;StSourceIdentityReply(blob,&bound,0,0,&source);RtlCopyMemory(output,&source,sizeof(source));*returned=sizeof(source);return STATUS_SUCCESS;}
        if(request.Command==10&&reply.Count){publicationStatus=StPausePublication();if(!NT_SUCCESS(publicationStatus))return publicationStatus;}
        if(strong){wide.Reply=reply;wide.Provider=SbHealth.Provider;wide.Generation=bound.Generation;RtlCopyMemory(output,&wide,sizeof(wide));}
        else RtlCopyMemory(output,&reply,sizeof(reply));
        if(reply.Count)RtlCopyMemory((PUCHAR)output+replyBytes,blob->Bytes+request.Offset,reply.Count);*returned=replyBytes+reply.Count;
        publicationStatus=STATUS_SUCCESS;
    }
    __finally{if(publicationEvidence.Id){KeAcquireSpinLock(&StLock,&old);StNotice(14,0,publicationStatus,&publicationEvidence);KeReleaseSpinLock(&StLock,old);}StRelease(blob);}
    return STATUS_SUCCESS;
}
static VOID StProcess(PEPROCESS process,HANDLE pid,PPS_CREATE_NOTIFY_INFO info)
{
    if(!StAcquire())return;
    __try{StProcessCore(process,pid,info);}__finally{ExReleaseRundownProtection(&StRundown);}
}
static VOID StPostCreate(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,FLT_POST_OPERATION_FLAGS flags,BOOLEAN preQualified,ULONG mappedRequestedAccess,ULONG originalRequestedAccess)
{
    if(!StAcquire())return;
    __try{StPostCreateCore(data,objects,flags,preQualified,mappedRequestedAccess,originalRequestedAccess);}__finally{ExReleaseRundownProtection(&StRundown);}
}
static NTSTATUS StMessage(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned,ULONGLONG instance)
{
    NTSTATUS status;BOOLEAN publication=FALSE;
    if(!StAcquire())return STATUS_DELETE_PENDING;
    __try{
        if(inputBytes>=8&&(((ST_REQUEST*)input)->Command==10||((ST_REQUEST*)input)->Command==13||((ST_REQUEST*)input)->Command==19)){
            if(!ExAcquireRundownProtection(&StPublicationRundown))return STATUS_DELETE_PENDING;
            publication=TRUE;InterlockedIncrement(&StPublicationInFlight);
        }
        status=StMessageCore(input,inputBytes,output,outputBytes,returned,instance);
    }__finally{if(publication){InterlockedDecrement(&StPublicationInFlight);ExReleaseRundownProtection(&StPublicationRundown);}ExReleaseRundownProtection(&StRundown);}
    return status;
}
