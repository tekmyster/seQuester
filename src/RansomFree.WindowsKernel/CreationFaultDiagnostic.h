#pragma once
// Compile-only laboratory control. Never included in ordinary staging builds.
// All selectors/journal fields are scalars; no process or file pointer escapes.
#define CF_ROWS 64u
#define CF_MISMATCH 1u
#define CF_LOOKUP_FAILURE 2u
#define CF_ALLOCATION_FAILURE 3u
#define CF_BIND_FAILURE 4u
#define CF_CAPACITY_TWO 5u
typedef struct _CF_REQUEST {
    ULONG Version,Command;UUID Provider;
    ULONGLONG CreatorPid,CreatorCreated,Scenario;
    ULONG Mode,Count,Index,Reserved;
} CF_REQUEST;
C_ASSERT(sizeof(CF_REQUEST)==64);
typedef struct _CF_ROW {
    ULONG Version,Size,Kind,Mode;
    UUID Provider;
    ULONGLONG Scenario,ArmGeneration,CreatorPid,CreatorCreated,Candidate,Pid,Created,ProcessGeneration,Started,Finished;
    ULONG SelectorStatus,InjectedStatus,MetadataOutcome,Terminal;
} CF_ROW;
C_ASSERT(sizeof(CF_ROW)==128);
typedef struct _CF_STATE {
    ULONG Version,Size,Active,Stopped;
    UUID Provider;
    ULONGLONG Scenario,ArmGeneration,CreatorPid,CreatorCreated;
    ULONG Mode,Remaining,Pending,ReservedRows;
} CF_STATE;
C_ASSERT(sizeof(CF_STATE)==80);
typedef struct _CF_SELECTION {ULONGLONG Scenario,ArmGeneration;ULONG Index,Mode;} CF_SELECTION;
static KSPIN_LOCK CfLock;
static CF_STATE CfState;
static CF_ROW CfRows[CF_ROWS];
static ULONG CfNext,CfEnd;
static ULONG CfInconsistent;
static ULONGLONG CfCallbacksRemoved;
// Only the diagnostic control/unload paths take this mutex. Callbacks never do.
static KMUTEX CfUnregisterMutex;
typedef struct _CF_HEALTH {
    ULONG Version,Size,Stopped,Pending;UUID Provider;
    ULONG Selected,Finalized,StopRows,Inconsistent;
    ULONGLONG CallbacksRemoved,LastFinish;
} CF_HEALTH;
C_ASSERT(sizeof(CF_HEALTH)==64);
static NTSTATUS DiagUnregister(VOID);
static VOID CfInitialize(VOID)
{
    KeInitializeSpinLock(&CfLock);CfState.Version=1;CfState.Size=sizeof(CfState);CfState.Provider=SbHealth.Provider;
    KeInitializeMutex(&CfUnregisterMutex,0);
    // Slot zero is permanently reserved for STOP; no journal wrap/overwrite.
    CfState.ReservedRows=1;
}
static VOID CfRowInitialize(CF_ROW* row,ULONG kind)
{
    row->Version=1;row->Size=sizeof(*row);row->Kind=kind;row->Provider=CfState.Provider;
    row->Scenario=CfState.Scenario;row->ArmGeneration=CfState.ArmGeneration;
    row->CreatorPid=CfState.CreatorPid;row->CreatorCreated=CfState.CreatorCreated;row->Mode=CfState.Mode;
    row->Started=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
}
static VOID CfStop(VOID)
{
    KIRQL old;KeAcquireSpinLock(&CfLock,&old);
    if(!CfState.Stopped){
        CfRowInitialize(&CfRows[0],4);CfRows[0].Finished=CfRows[0].Started;
        CfState.Active=0;CfState.Stopped=1;if(CfState.ArmGeneration!=MAXULONGLONG)CfState.ArmGeneration++;
    }
    KeReleaseSpinLock(&CfLock,old);
}
// Caller holds no St/Sb/queue/object lock. Validate the current owning creator,
// then recheck configuration after the pageable lookup before consuming a slot.
static CF_SELECTION CfSelect(PPS_CREATE_NOTIFY_INFO info,ULONGLONG candidate,HANDLE pid,ULONGLONG created)
{
    CF_SELECTION result={0};CF_STATE state;KIRQL old;PEPROCESS owner=NULL;NTSTATUS status;ULONGLONG started=0;
    KeAcquireSpinLock(&CfLock,&old);state=CfState;KeReleaseSpinLock(&CfLock,old);
    if(!state.Active||state.Stopped||!state.Remaining||!candidate||
       (ULONGLONG)info->CreatingThreadId.UniqueProcess!=state.CreatorPid||
       info->CreatingThreadId.UniqueProcess!=PsGetCurrentProcessId()||info->CreatingThreadId.UniqueThread!=PsGetCurrentThreadId())return result;
    status=PsLookupProcessByProcessId(info->CreatingThreadId.UniqueProcess,&owner);
    if(NT_SUCCESS(status)){started=(ULONGLONG)PsGetProcessCreateTimeQuadPart(owner);ObDereferenceObject(owner);}
    if(!NT_SUCCESS(status)||started!=state.CreatorCreated)return result;
    KeAcquireSpinLock(&CfLock,&old);
    if(CfState.Active&&!CfState.Stopped&&CfState.Remaining&&CfState.Scenario==state.Scenario&&
       CfState.ArmGeneration==state.ArmGeneration&&CfState.CreatorPid==state.CreatorPid&&CfState.CreatorCreated==state.CreatorCreated){
        CF_ROW* row=&CfRows[CfNext];
        result.Scenario=state.Scenario;result.ArmGeneration=state.ArmGeneration;result.Index=CfNext++;result.Mode=state.Mode;
        CfRowInitialize(row,2);row->Candidate=candidate;row->Pid=(ULONGLONG)pid;row->Created=created;row->SelectorStatus=(ULONG)status;
        row->InjectedStatus=state.Mode==CF_LOOKUP_FAILURE?(ULONG)STATUS_ACCESS_DENIED:state.Mode==CF_ALLOCATION_FAILURE?(ULONG)STATUS_INSUFFICIENT_RESOURCES:0;
        CfState.Remaining--;CfState.Pending++;
    }
    KeReleaseSpinLock(&CfLock,old);return result;
}
// Finalize exactly the reserved invocation row after all existing locks release.
// Terminal 1 bound, 2 bind-failed, 3 candidate gone, 4 STOP suppressed,
// 5 bound then STOP, 6 bind-failed then STOP, 7 pending-accounting inconsistency.
static VOID CfFinish(CF_SELECTION selection,ULONG metadataOutcome,ULONGLONG generation,BOOLEAN attached)
{
    KIRQL old;CF_ROW* row;if(!selection.Mode)return;
    KeAcquireSpinLock(&CfLock,&old);
    if(selection.Index>=CF_ROWS){CfInconsistent=1;KeReleaseSpinLock(&CfLock,old);return;}
    row=&CfRows[selection.Index];
    if(row->Kind==2&&row->Scenario==selection.Scenario&&row->ArmGeneration==selection.ArmGeneration&&!row->Terminal){
        row->MetadataOutcome=metadataOutcome;row->ProcessGeneration=generation;
        row->Terminal=attached?(generation?(CfState.Stopped?5:1):(CfState.Stopped?6:2)):CfState.Stopped?4:3;
        row->Finished=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
        if(CfState.Pending)CfState.Pending--;else {row->Terminal=7;CfInconsistent=1;}
    }else CfInconsistent=1; // Never overwrite an existing terminal or identity.
    KeReleaseSpinLock(&CfLock,old);
}
// Called only after existing process/image callback removal returns. StQuiesce
// itself precedes callback removal and is NOT a drained-callback proof.
static VOID CfRemovedHealth(CF_HEALTH* health)
{
    KIRQL old;ULONG i;RtlZeroMemory(health,sizeof(*health));
    KeAcquireSpinLock(&CfLock,&old);
    if(!CfCallbacksRemoved)CfCallbacksRemoved=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    health->Version=1;health->Size=sizeof(*health);health->Provider=CfState.Provider;
    health->Stopped=CfState.Stopped;health->Pending=CfState.Pending;health->CallbacksRemoved=CfCallbacksRemoved;
    for(i=0;i<CfState.ReservedRows;i++){
        CF_ROW* row=&CfRows[i];
        if(row->Kind==4)health->StopRows++;
        if(row->Kind==2){health->Selected++;if(row->Terminal&&row->Finished)health->Finalized++;
            if(row->Finished>health->LastFinish)health->LastFinish=row->Finished;}
    }
    if(!health->Stopped||health->Pending||health->Selected!=health->Finalized||health->StopRows!=1)CfInconsistent=1;
    health->Inconsistent=CfInconsistent;KeReleaseSpinLock(&CfLock,old);
}
// Commands 29 ARM, 30 CLEAR, 31 state, 32 one initialized journal row,
// 33 owner-bound removal of existing callback roots and scalar health reply.
// A consumed invocation has Terminal=0 until its terminal update is committed.
// All requests bind to the provider; mutations also bind to owner PID/start.
// Mutations look up the owner outside locks. STOP retains the journal.
static NTSTATUS CfMessage(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned,BOOLEAN enabled)
{
    CF_REQUEST request;KIRQL old;NTSTATUS status=STATUS_SUCCESS;PEPROCESS owner=NULL;ULONGLONG started=0;
    ULONG needed;CF_ROW rowReply={0};CF_STATE stateReply={0};
    if(inputBytes!=sizeof(request))return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&request,input,sizeof(request));
    if(request.Version!=4||request.Command<29||request.Command>33||request.Reserved||
       !RtlEqualMemory(&request.Provider,&CfState.Provider,sizeof(UUID)))return STATUS_INVALID_PARAMETER;
    needed=request.Command==33?sizeof(CF_HEALTH):request.Command==32?sizeof(CF_ROW):sizeof(CF_STATE);
    if(!output||outputBytes<needed){*returned=needed;return STATUS_BUFFER_TOO_SMALL;}
    if(request.Command==29){
        if(!enabled||request.Scenario||request.Index||request.Mode<1||request.Mode>5||
           request.Count!=(request.Mode==CF_CAPACITY_TWO?3u:1u)||(ULONGLONG)PsGetCurrentProcessId()!=request.CreatorPid)return STATUS_INVALID_PARAMETER;
    }else if(request.Mode||request.Count||(request.Command!=32&&request.Index))return STATUS_INVALID_PARAMETER;
    // Check the wait/pageable-lookup context before looking up the owner.
    // Command33 is reached only by synchronous FilterSendMessage.
    if(request.Command==33&&(KeGetCurrentIrql()!=PASSIVE_LEVEL||KeAreAllApcsDisabled()))return STATUS_INVALID_DEVICE_STATE;
    if(request.Command==29||request.Command==30||request.Command==33){
        if((ULONGLONG)PsGetCurrentProcessId()!=request.CreatorPid)return STATUS_NOT_FOUND;
        status=PsLookupProcessByProcessId((HANDLE)request.CreatorPid,&owner);
        if(NT_SUCCESS(status)){started=(ULONGLONG)PsGetProcessCreateTimeQuadPart(owner);ObDereferenceObject(owner);}
        if(!NT_SUCCESS(status))return status;
        if(!started||started!=request.CreatorCreated)return STATUS_NOT_FOUND;
    }
    if(request.Command==33){
        CF_HEALTH health;BOOLEAN ownerMatches;
        KeAcquireSpinLock(&CfLock,&old);
        ownerMatches=CfState.Stopped&&request.Scenario==CfState.Scenario&&request.CreatorPid==CfState.CreatorPid&&request.CreatorCreated==CfState.CreatorCreated;
        KeReleaseSpinLock(&CfLock,old);
        if(!ownerMatches)return STATUS_NOT_FOUND;
        // No Cf/St/Sb/queue lock is held. The existing removal API waits for
        // every callback; no callback pause or user-mode dependency is added.
        status=DiagUnregister();if(!NT_SUCCESS(status))return status;
        CfRemovedHealth(&health);RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    KeAcquireSpinLock(&CfLock,&old);
    if(request.Command==29){
        if(CfState.Active||CfState.Stopped||CfState.Pending)status=STATUS_DEVICE_BUSY;
        else if(CfState.Scenario==MAXULONGLONG||CfState.ArmGeneration==MAXULONGLONG||CfState.ReservedRows+request.Count+2>CF_ROWS)status=STATUS_INSUFFICIENT_RESOURCES;
        else{
            CfState.Scenario++;CfState.ArmGeneration++;CfState.CreatorPid=request.CreatorPid;CfState.CreatorCreated=request.CreatorCreated;
            CfState.Mode=request.Mode;CfState.Remaining=request.Count;CfState.Active=1;
            CfRowInitialize(&CfRows[CfState.ReservedRows],1);CfRows[CfState.ReservedRows].Finished=CfRows[CfState.ReservedRows].Started;
            CfNext=CfState.ReservedRows+1;CfEnd=CfNext+request.Count;CfState.ReservedRows=CfEnd+1;
        }
    }else if(request.Command==30){
        if(!CfState.Active||CfState.Stopped||request.Scenario!=CfState.Scenario||request.CreatorPid!=CfState.CreatorPid||request.CreatorCreated!=CfState.CreatorCreated||(ULONGLONG)PsGetCurrentProcessId()!=CfState.CreatorPid)status=STATUS_NOT_FOUND;
        else{
            CfRowInitialize(&CfRows[CfEnd],3);CfRows[CfEnd].Finished=CfRows[CfEnd].Started;
            CfState.Active=0;CfState.Remaining=0;if(CfState.ArmGeneration!=MAXULONGLONG)CfState.ArmGeneration++;
        }
    }else if(request.Command==32){
        if(request.Index>=CfState.ReservedRows)status=STATUS_NO_MORE_ENTRIES;
        else if(!CfRows[request.Index].Kind||CfRows[request.Index].Version!=1||CfRows[request.Index].Size!=sizeof(CF_ROW))status=STATUS_NOT_FOUND;
    }
    if(NT_SUCCESS(status)){if(request.Command==32)rowReply=CfRows[request.Index];else stateReply=CfState;}
    KeReleaseSpinLock(&CfLock,old);
    if(NT_SUCCESS(status)){RtlCopyMemory(output,request.Command==32?(PVOID)&rowReply:(PVOID)&stateReply,needed);*returned=needed;}
    return status;
}
