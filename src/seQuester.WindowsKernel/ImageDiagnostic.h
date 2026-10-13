#pragma once
// Qualification-only, no-I/O image/process association probe. Compile-time opt-in;
// no actor bytes, file handles, kernel pointers or trust verdicts cross this port.
#define SQ_DIAG_START 6
#define SQ_DIAG_READ 7
#define SQ_DIAG_GET_HEALTH 8
#define SQ_DIAG_STOP 9
#define SQ_DIAG_POOL 128
#define SQ_DIAG_RING 2048
typedef struct _SQ_DIAG_ROW {
    ULONG Version, Size, Kind, Flags;
    ULONGLONG Epoch, Sequence, ProcessId, ProcessCreated, ThreadId, CandidateId;
    LONGLONG Qpc;
    ULONG Irql, Candidates, Matches, Released;
} SQ_DIAG_ROW;
C_ASSERT(sizeof(SQ_DIAG_ROW)==88);
typedef struct _SQ_DIAG_HEALTH {
    ULONG Version, Size;
    ULONGLONG Epoch, Sequence, Lost, PoolDrops, Taken, Released;
    ULONG Live, Queued, Enabled, Reserved;
} SQ_DIAG_HEALTH;
C_ASSERT(sizeof(SQ_DIAG_HEALTH)==72);
typedef struct _SQ_DIAG_CANDIDATE {
    PFILE_OBJECT File;
    ULONGLONG Pid, Created, Id;
} SQ_DIAG_CANDIDATE;
static KSPIN_LOCK DiagLock;
static SQ_DIAG_CANDIDATE DiagCandidates[SQ_DIAG_POOL];
static SQ_DIAG_ROW DiagRows[SQ_DIAG_RING];
static SQ_DIAG_HEALTH DiagHealth;
static ULONG DiagReadIndex, DiagWriteIndex;
static ULONGLONG DiagNextCandidate;
static BOOLEAN DiagImageRegistered, DiagProcessRegistered;
static volatile LONG DiagEnabled;
static volatile LONG DiagStopping;

// Called only while DiagLock is held. Sequence gaps and ring loss remain visible.
static VOID DiagAppend(SQ_DIAG_ROW* row)
{
    row->Version=1;row->Size=sizeof(*row);row->Epoch=DiagHealth.Epoch;
    row->Sequence=++DiagHealth.Sequence;
    if(DiagHealth.Queued==SQ_DIAG_RING){DiagHealth.Lost++;return;}
    DiagRows[DiagWriteIndex]=*row;DiagWriteIndex=(DiagWriteIndex+1)%SQ_DIAG_RING;DiagHealth.Queued++;
}
static VOID DiagFill(SQ_DIAG_ROW* row,ULONG kind,HANDLE pid,LONGLONG created,PFILE_OBJECT file)
{
    RtlZeroMemory(row,sizeof(*row));row->Kind=kind;row->ProcessId=(ULONGLONG)pid;
    row->ProcessCreated=(ULONGLONG)created;row->ThreadId=(ULONGLONG)PsGetCurrentThreadId();
    row->Qpc=KeQueryPerformanceCounter(NULL).QuadPart;row->Irql=KeGetCurrentIrql();
    if(KeAreAllApcsDisabled())row->Flags|=2;
    if(KeAreApcsDisabled())row->Flags|=4;
    // Observation during a documented live callback, not an open-state lock.
    if(file){if(FlagOn(file->Flags,FO_CLEANUP_COMPLETE))row->Flags|=8;if(FlagOn(file->Flags,FO_HANDLE_CREATED))row->Flags|=16;}
}
static VOID DiagImage(PUNICODE_STRING name,HANDLE pid,PIMAGE_INFO info)
{
    SQ_DIAG_ROW row;PFILE_OBJECT file=NULL;KIRQL old;ULONG i;BOOLEAN kept=FALSE;
    UNREFERENCED_PARAMETER(name);
    if(!InterlockedCompareExchange(&DiagEnabled,0,0)||!pid||info->SystemModeImage)return;
    if(info->ExtendedInfoPresent){
        PIMAGE_INFO_EX extended=CONTAINING_RECORD(info,IMAGE_INFO_EX,ImageInfo);
        if(extended->Size>=FIELD_OFFSET(IMAGE_INFO_EX,FileObject)+sizeof(PVOID))file=extended->FileObject;
    }
    if(PsGetCurrentProcessId()!=pid||!file){
        DiagFill(&row,4,pid,0,NULL);
        KeAcquireSpinLock(&DiagLock,&old);if(DiagEnabled)DiagAppend(&row);KeReleaseSpinLock(&DiagLock,old);return;
    }
    DiagFill(&row,1,pid,PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess()),file);row.Flags|=1;
#ifdef SQ_POST_CREATE_DIAGNOSTIC
    // This variant records image state only. Owned candidates originate from
    // successful post-CREATE; an image notification cannot reopen their lifetime.
    UNREFERENCED_PARAMETER(i);UNREFERENCED_PARAMETER(kept);
    KeAcquireSpinLock(&DiagLock,&old);if(DiagEnabled)DiagAppend(&row);KeReleaseSpinLock(&DiagLock,old);return;
#else
    // IMAGE_INFO_EX explicitly allows an owned reference. No section creation,
    // path lookup, file read, worker wait or process lookup occurs here.
    ObReferenceObject(file);
    KeAcquireSpinLock(&DiagLock,&old);
    if(DiagEnabled){
        for(i=0;i<SQ_DIAG_POOL;i++)if(!DiagCandidates[i].File){
            DiagCandidates[i].File=file;DiagCandidates[i].Pid=row.ProcessId;
            DiagCandidates[i].Created=row.ProcessCreated;DiagCandidates[i].Id=++DiagNextCandidate;
            row.CandidateId=DiagNextCandidate;DiagHealth.Live++;DiagHealth.Taken++;kept=TRUE;break;
        }
        if(!kept){DiagHealth.PoolDrops++;row.Flags|=32;}
        DiagAppend(&row);
    }
    KeReleaseSpinLock(&DiagLock,old);
    if(!kept)ObDereferenceObjectDeferDelete(file);
#endif
}
#ifdef SQ_POST_CREATE_DIAGNOSTIC
static BOOLEAN DiagWantsCreate(PFLT_CALLBACK_DATA data)
{
    return InterlockedCompareExchange(&DiagEnabled,0,0)&&data->Iopb->MajorFunction==IRP_MJ_CREATE&&
        data->Iopb->Parameters.Create.SecurityContext&&
        SqExecutableCandidateAccess(data->Iopb->Parameters.Create.SecurityContext->DesiredAccess)&&
        !FlagOn(data->Iopb->Parameters.Create.Options,FILE_DIRECTORY_FILE);
}
static VOID DiagPostCreate(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,FLT_POST_OPERATION_FLAGS flags)
{
    SQ_DIAG_ROW row;KIRQL old;ULONG i;BOOLEAN kept=FALSE;NTSTATUS status;
    if(!DiagWantsCreate(data)||FlagOn(flags,FLTFL_POST_OPERATION_DRAINING)||
        !NT_SUCCESS(data->IoStatus.Status)||data->IoStatus.Status==STATUS_REPARSE||!objects->FileObject)return;
    DiagFill(&row,5,PsGetCurrentProcessId(),PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess()),objects->FileObject);
    // Reference the live, typed file object. No bytes, names, sections, open
    // handles or synchronous workers are acquired by this diagnostic.
    status=ObReferenceObjectByPointer(objects->FileObject,0,*IoFileObjectType,KernelMode);
    if(!NT_SUCCESS(status)){row.Flags|=64;row.Candidates=(ULONG)status;KeAcquireSpinLock(&DiagLock,&old);if(DiagEnabled)DiagAppend(&row);KeReleaseSpinLock(&DiagLock,old);return;}
    KeAcquireSpinLock(&DiagLock,&old);
    if(DiagEnabled){
        for(i=0;i<SQ_DIAG_POOL;i++)if(!DiagCandidates[i].File){
            DiagCandidates[i].File=objects->FileObject;DiagCandidates[i].Id=++DiagNextCandidate;
            // The opener is not necessarily the process being created. Only a
            // later live process-create FileObject equality can bind this candidate.
            row.CandidateId=DiagNextCandidate;DiagHealth.Live++;DiagHealth.Taken++;kept=TRUE;break;
        }
        if(!kept){DiagHealth.PoolDrops++;row.Flags|=32;}
        DiagAppend(&row);
    }
    KeReleaseSpinLock(&DiagLock,old);if(!kept)ObDereferenceObjectDeferDelete(objects->FileObject);
}
static FLT_PREOP_CALLBACK_STATUS DiagCleanup(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
{
    SQ_DIAG_ROW row;PFILE_OBJECT release[SQ_DIAG_POOL];ULONG i,count=0;KIRQL old;
    UNREFERENCED_PARAMETER(data);*context=NULL;
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StSweep(FALSE,objects->FileObject);
#endif
    if(!InterlockedCompareExchange(&DiagEnabled,0,0)||!objects->FileObject)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    DiagFill(&row,6,PsGetCurrentProcessId(),PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess()),objects->FileObject);
    KeAcquireSpinLock(&DiagLock,&old);
    if(DiagEnabled){
        for(i=0;i<SQ_DIAG_POOL;i++)if(DiagCandidates[i].File==objects->FileObject){
            release[count++]=DiagCandidates[i].File;row.CandidateId=DiagCandidates[i].Id;
            RtlZeroMemory(&DiagCandidates[i],sizeof(DiagCandidates[i]));DiagHealth.Live--;
        }
        if(count){row.Released=count;DiagHealth.Released+=count;DiagAppend(&row);}
    }
    KeReleaseSpinLock(&DiagLock,old);for(i=0;i<count;i++)ObDereferenceObjectDeferDelete(release[i]);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
#endif
static VOID DiagProcess(PEPROCESS process,HANDLE pid,PPS_CREATE_NOTIFY_INFO info)
{
    SQ_DIAG_ROW row;PFILE_OBJECT release[SQ_DIAG_POOL];ULONG i,count=0;KIRQL old;
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StProcess(process,pid,info);
#endif
    if(!InterlockedCompareExchange(&DiagEnabled,0,0))return;
    DiagFill(&row,info?2:3,pid,PsGetProcessCreateTimeQuadPart(process),info?info->FileObject:NULL);
    KeAcquireSpinLock(&DiagLock,&old);
    if(DiagEnabled){
        for(i=0;i<SQ_DIAG_POOL;i++){
            SQ_DIAG_CANDIDATE* candidate=&DiagCandidates[i];
#ifdef SQ_POST_CREATE_DIAGNOSTIC
            if(!candidate->File||!info)continue;
            row.Candidates++;
            if(info->FileObject&&candidate->File==info->FileObject){
                row.Matches++;row.CandidateId=candidate->Id;release[count++]=candidate->File;
                RtlZeroMemory(candidate,sizeof(*candidate));DiagHealth.Live--;
            }
#else
            if(!candidate->File||candidate->Pid!=row.ProcessId||candidate->Created!=row.ProcessCreated)continue;
            row.Candidates++;
            if(info){
                // Borrowed pointer is compared only while this callback is live.
                // It is never copied into retained state or referenced for later use.
                if(info->FileObject&&candidate->File==info->FileObject){row.Matches++;row.CandidateId=candidate->Id;}
            }else{release[count++]=candidate->File;RtlZeroMemory(candidate,sizeof(*candidate));DiagHealth.Live--;}
#endif
        }
        row.Released=count;DiagHealth.Released+=count;DiagAppend(&row);
    }
    KeReleaseSpinLock(&DiagLock,old);
    for(i=0;i<count;i++)ObDereferenceObjectDeferDelete(release[i]);
}
static VOID DiagDisable(VOID)
{
    PFILE_OBJECT release[SQ_DIAG_POOL];ULONG i,count=0;KIRQL old;
    KeAcquireSpinLock(&DiagLock,&old);InterlockedExchange(&DiagEnabled,0);DiagHealth.Enabled=0;
    for(i=0;i<SQ_DIAG_POOL;i++)if(DiagCandidates[i].File){release[count++]=DiagCandidates[i].File;RtlZeroMemory(&DiagCandidates[i],sizeof(DiagCandidates[i]));}
    DiagHealth.Released+=count;DiagHealth.Live=0;KeReleaseSpinLock(&DiagLock,old);
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    StDisable();
#endif
    for(i=0;i<count;i++)ObDereferenceObjectDeferDelete(release[i]);
}
static NTSTATUS DiagUnregisterCore(VOID)
{
    InterlockedExchange(&DiagStopping,1);
    DiagDisable();
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
    {NTSTATUS status=StQuiesce();if(status!=STATUS_SUCCESS)return status;}
#endif
    if(DiagProcessRegistered){
        NTSTATUS status=PsSetCreateProcessNotifyRoutineEx(DiagProcess,TRUE);
        if(!NT_SUCCESS(status))return status;
        DiagProcessRegistered=FALSE;
    }
    if(DiagImageRegistered){
        NTSTATUS status=PsRemoveLoadImageNotifyRoutine(DiagImage);
        if(!NT_SUCCESS(status))return status;
        DiagImageRegistered=FALSE;
    }
    // Removal waits for callbacks, including reference releases outside the lock.
    return STATUS_SUCCESS;
}
static NTSTATUS DiagUnregister(VOID)
{
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    NTSTATUS status=KeWaitForSingleObject(&CfUnregisterMutex,Executive,KernelMode,FALSE,NULL);
    if(status!=STATUS_SUCCESS)return status;
    // The explicit diagnostic quiesce command and ordinary unload share the
    // existing removal path. Never concurrently remove roots or close the
    // worker handle. This mutex is never acquired by a process callback.
    __try{status=DiagUnregisterCore();}__finally{KeReleaseMutex(&CfUnregisterMutex,FALSE);}
    return status;
#else
    return DiagUnregisterCore();
#endif
}
static NTSTATUS DiagRegister(VOID)
{
    NTSTATUS status;
    status=PsSetLoadImageNotifyRoutine(DiagImage);if(!NT_SUCCESS(status))return status;DiagImageRegistered=TRUE;
    status=PsSetCreateProcessNotifyRoutineEx(DiagProcess,FALSE);
    if(NT_SUCCESS(status))DiagProcessRegistered=TRUE;else DiagUnregister();return status;
}
static NTSTATUS DiagMessage(ULONG command,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    KIRQL old;SQ_DIAG_ROW row;SQ_DIAG_HEALTH health;BOOLEAN found=FALSE;
    if(inputBytes!=8)return STATUS_INVALID_PARAMETER;
    if(command==SQ_DIAG_START){
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
        if(!InterlockedCompareExchange(&StWorkerReady,0,0)||InterlockedCompareExchange(&StStopInitiated,0,0))return STATUS_DEVICE_NOT_READY;
#endif
        // One diagnostic epoch per driver load. Explicit stop cannot race a
        // restart into associating an old callback with a new generation.
        KeAcquireSpinLock(&DiagLock,&old);
        if(DiagStopping||!DiagImageRegistered||!DiagProcessRegistered||DiagHealth.Epoch||DiagEnabled||DiagHealth.Live){KeReleaseSpinLock(&DiagLock,old);return STATUS_DEVICE_BUSY;}
        RtlZeroMemory(&DiagHealth,sizeof(DiagHealth));DiagHealth.Version=1;DiagHealth.Size=sizeof(DiagHealth);
#ifdef SQ_POST_CREATE_DIAGNOSTIC
        DiagHealth.Reserved=1; // Explicit diagnostic mode; wire event protocol remains 4.
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
        DiagHealth.Reserved=2;
#endif
#endif
        DiagHealth.Epoch=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;DiagHealth.Enabled=1;
        DiagReadIndex=DiagWriteIndex=0;InterlockedExchange(&DiagEnabled,1);
#ifdef SQ_EXECUTABLE_STAGING_DIAGNOSTIC
        InterlockedExchange(&StEnabled,1);
#endif
        KeReleaseSpinLock(&DiagLock,old);
        return STATUS_SUCCESS;
    }
    if(command==SQ_DIAG_STOP){DiagDisable();return STATUS_SUCCESS;}
    if(command==SQ_DIAG_GET_HEALTH){
        if(!output||outputBytes<sizeof(health))return STATUS_BUFFER_TOO_SMALL;
        KeAcquireSpinLock(&DiagLock,&old);health=DiagHealth;KeReleaseSpinLock(&DiagLock,old);
        RtlCopyMemory(output,&health,sizeof(health));*returned=sizeof(health);return STATUS_SUCCESS;
    }
    if(command==SQ_DIAG_READ){
        if(!output||outputBytes<sizeof(row))return STATUS_BUFFER_TOO_SMALL;
        KeAcquireSpinLock(&DiagLock,&old);
        if(DiagHealth.Queued){row=DiagRows[DiagReadIndex];DiagReadIndex=(DiagReadIndex+1)%SQ_DIAG_RING;DiagHealth.Queued--;found=TRUE;}
        KeReleaseSpinLock(&DiagLock,old);
        if(!found)return STATUS_NO_MORE_ENTRIES;
        RtlCopyMemory(output,&row,sizeof(row));*returned=sizeof(row);return STATUS_SUCCESS;
    }
    return STATUS_INVALID_PARAMETER;
}

