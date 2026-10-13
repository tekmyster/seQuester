#pragma once
// Opt-in laboratory companion to protocol-4 observations. Referenced process
// objects are private lookup keys; only opaque generations leave the kernel.
#define SB_CAPACITY 256
typedef struct _SB_BINDING {
    ULONG Version,Size,Flags,Status;
    UUID Provider;
    ULONGLONG Generation,Candidate,Pid,Created;
    ULONG ProviderStatus,Reason;
    ULONGLONG EventInstance,EventSequence;
} SB_BINDING;
C_ASSERT(sizeof(SB_BINDING)==88);
typedef struct _SB_PROCESS {
    PEPROCESS Process;
    ULONGLONG Generation,Candidate,Pid,Created;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
    ULONGLONG NegativeAssociation;
    ULONGLONG AcquisitionOriginCandidate;
    NTSTATUS AcquisitionStatus;
    ULONG AcquisitionState,AcquisitionStage,AcquisitionFlags;
#endif
} SB_PROCESS;
typedef struct _SB_HEALTH {
    ULONG Version,Size;
    UUID Provider;
    ULONG ProviderStatus,Capacity;
    ULONGLONG NextGeneration,ReferencesTaken,ReferencesReleased,CapacityMisses;
    ULONG Live,Stopped;
    ULONGLONG OperationPins,OperationPinsReleased;
} SB_HEALTH;
C_ASSERT(sizeof(SB_HEALTH)==88);
static KSPIN_LOCK SbLock;
static SB_PROCESS SbProcesses[SB_CAPACITY];
static SB_HEALTH SbHealth;
static BOOLEAN SbReady;
static NTSTATUS SbInitialize(VOID)
{
    NTSTATUS status;KeInitializeSpinLock(&SbLock);
    SbHealth.Version=1;SbHealth.Size=sizeof(SbHealth);SbHealth.Capacity=SB_CAPACITY;
    status=ExUuidCreate(&SbHealth.Provider);SbHealth.ProviderStatus=(ULONG)status;
    // Local-only UUIDs are explicitly scoped by the sensor identity at intake.
    if(status!=STATUS_SUCCESS&&status!=RPC_NT_UUID_LOCAL_ONLY)return status;
    SbReady=TRUE;return STATUS_SUCCESS;
}
static ULONGLONG SbBind(PEPROCESS process,HANDLE pid,ULONGLONG created,ULONGLONG candidate)
{
    ULONG i,slot=SB_CAPACITY;KIRQL old;ULONGLONG generation=0;
    KeAcquireSpinLock(&SbLock,&old);
    if(SbReady&&!SbHealth.Stopped&&SbHealth.NextGeneration!=MAXULONGLONG){
        for(i=0;i<SB_CAPACITY;i++){
            if(SbProcesses[i].Process==process)break; // Never silently rebind a live process.
            if(!SbProcesses[i].Process&&slot==SB_CAPACITY)slot=i;
        }
        if(i==SB_CAPACITY&&slot!=SB_CAPACITY){
            ObReferenceObject(process);
            SbProcesses[slot].Process=process;SbProcesses[slot].Pid=(ULONGLONG)pid;SbProcesses[slot].Created=created;
            SbProcesses[slot].Candidate=candidate;SbProcesses[slot].Generation=generation=++SbHealth.NextGeneration;
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
            SbProcesses[slot].AcquisitionState=candidate?SQ_ACQ_COPY_PENDING:SQ_ACQ_BYTES_UNAVAILABLE;
            SbProcesses[slot].AcquisitionStatus=candidate?STATUS_PENDING:STATUS_NOT_FOUND;
#endif
            SbHealth.Live++;SbHealth.ReferencesTaken++;
        }else SbHealth.CapacityMisses++;
    }
    KeReleaseSpinLock(&SbLock,old);return generation;
}
static VOID SbExit(PEPROCESS process)
{
    ULONG i;KIRQL old;PEPROCESS release=NULL;
    KeAcquireSpinLock(&SbLock,&old);
    for(i=0;i<SB_CAPACITY;i++)if(SbProcesses[i].Process==process){
        release=SbProcesses[i].Process;RtlZeroMemory(&SbProcesses[i],sizeof(SB_PROCESS));
        SbHealth.Live--;SbHealth.ReferencesReleased++;break;
    }
    KeReleaseSpinLock(&SbLock,old);if(release)ObDereferenceObjectDeferDelete(release);
}
static VOID SbStop(VOID)
{
    ULONG i;KIRQL old;
    KeAcquireSpinLock(&SbLock,&old);SbHealth.Stopped=1;KeReleaseSpinLock(&SbLock,old);
    for(i=0;i<SB_CAPACITY;i++){
        PEPROCESS release=NULL;KeAcquireSpinLock(&SbLock,&old);
        if(SbProcesses[i].Process){release=SbProcesses[i].Process;RtlZeroMemory(&SbProcesses[i],sizeof(SB_PROCESS));SbHealth.Live--;SbHealth.ReferencesReleased++;}
        KeReleaseSpinLock(&SbLock,old);if(release)ObDereferenceObjectDeferDelete(release);
    }
}
static VOID SbObserve(PEPROCESS process,ULONGLONG instance,ULONGLONG sequence,SB_BINDING* result)
{
    ULONG i;KIRQL old;RtlZeroMemory(result,sizeof(*result));result->Version=2;result->Size=sizeof(*result);
    result->EventInstance=instance;result->EventSequence=sequence;result->Status=(ULONG)STATUS_NOT_FOUND;result->Reason=1;
    KeAcquireSpinLock(&SbLock,&old);result->Provider=SbHealth.Provider;result->ProviderStatus=SbHealth.ProviderStatus;
    if(SbReady&&!SbHealth.Stopped&&process)for(i=0;i<SB_CAPACITY;i++)if(SbProcesses[i].Process==process&&SbProcesses[i].Candidate){
        const SB_PROCESS* p=&SbProcesses[i];result->Flags=1;result->Status=STATUS_SUCCESS;result->Reason=0;
        result->Generation=p->Generation;result->Candidate=p->Candidate;result->Pid=p->Pid;result->Created=p->Created;break;
    }
    if(!process)result->Reason=2;else if(SbHealth.Stopped)result->Reason=3;
    KeReleaseSpinLock(&SbLock,old);
}
#ifdef SQ_ACQUISITION_OUTCOME_DIAGNOSTIC
// StLock -> SbLock. Exact opaque generation only; no PID/path backfill.
static VOID SbAcquisitionSet(ULONGLONG generation,ULONG state,ULONG stage,NTSTATUS status,ULONGLONG negative,ULONGLONG origin,ULONG flags)
{
    ULONG i;KIRQL old;KeAcquireSpinLock(&SbLock,&old);
    if(generation)for(i=0;i<SB_CAPACITY;i++)if(SbProcesses[i].Process&&SbProcesses[i].Generation==generation){
        if((SbProcesses[i].AcquisitionState==SQ_ACQ_PREBIND_REFUSAL||SbProcesses[i].AcquisitionState==SQ_ACQ_BOUND_COPY_FAILURE)&&state==SQ_ACQ_BYTES_UNAVAILABLE)break;
        SbProcesses[i].AcquisitionState=state;SbProcesses[i].AcquisitionStage=stage;
        SbProcesses[i].AcquisitionStatus=status;SbProcesses[i].NegativeAssociation=negative;
        // The origin is diagnostic only; it never authorizes byte retrieval.
        SbProcesses[i].AcquisitionOriginCandidate=origin;SbProcesses[i].AcquisitionFlags=flags;break;
    }
    KeReleaseSpinLock(&SbLock,old);
}
// A candidate ID is unique in this provider epoch and was attached only by exact
// process-create FILE_OBJECT equality. This preserves completion after TTL has
// detached the entry; it never searches by PID/path or guesses a new association.
static VOID SbAcquisitionFailCandidate(ULONGLONG candidate,ULONG stage,NTSTATUS status,ULONG flags)
{
    ULONG i;KIRQL old;KeAcquireSpinLock(&SbLock,&old);
    if(candidate)for(i=0;i<SB_CAPACITY;i++){
        SB_PROCESS* p=&SbProcesses[i];
        if(!p->Process||p->Candidate!=candidate||p->AcquisitionState!=SQ_ACQ_COPY_PENDING)continue;
        p->AcquisitionState=SQ_ACQ_BOUND_COPY_FAILURE;p->AcquisitionStage=stage;
        p->AcquisitionStatus=status;p->NegativeAssociation=0;p->AcquisitionOriginCandidate=candidate;p->AcquisitionFlags=flags;break;
    }
    KeReleaseSpinLock(&SbLock,old);
}
static VOID SbAcquisitionObserve(PEPROCESS process,SQ_ACQUISITION_OUTCOME* result)
{
    ULONG i;KIRQL old;KeAcquireSpinLock(&SbLock,&old);result->Provider=SbHealth.Provider;
    if(SbReady&&!SbHealth.Stopped&&process)for(i=0;i<SB_CAPACITY;i++)if(SbProcesses[i].Process==process){
        const SB_PROCESS* p=&SbProcesses[i];result->ProcessGeneration=p->Generation;
        result->NegativeAssociation=p->NegativeAssociation;result->OriginCandidate=p->AcquisitionState==SQ_ACQ_PREBIND_REFUSAL?p->AcquisitionOriginCandidate:p->Candidate;
        result->OriginGeneration=p->Candidate&&p->AcquisitionState!=SQ_ACQ_PREBIND_REFUSAL?p->Generation:0;
        result->State=p->AcquisitionState;result->Stage=p->AcquisitionStage;
        result->NativeStatus=p->AcquisitionStatus;result->Certainty=1;result->Flags=p->AcquisitionFlags;break;
    }
    KeReleaseSpinLock(&SbLock,old);
}
#endif
