#pragma once
// Exact FILE_OBJECT equality at the one process-create callback only. No bytes,
// path lookup, opener attribution, retry at another process creation, or I/O.
#define ST_NEG_CAPACITY 128u
typedef struct _ST_NEG_ASSOC {
    PFILE_OBJECT File;
    ULONGLONG Id,Deadline,OriginCandidate;
    NTSTATUS Status;
    ULONG State,Stage,Flags;
    BOOLEAN BindAttempted;
} ST_NEG_ASSOC;
static ST_NEG_ASSOC StNegatives[ST_NEG_CAPACITY];
static ULONGLONG StNegativeNext,StNegativeGapCount,StNegativeGapQpc;
static ULONGLONG StNegativeReferences,StNegativeReleased;
// StLock held. On success the caller transfers exactly one existing reference.
static BOOLEAN StNegativeStoreLocked(PFILE_OBJECT file,ULONGLONG origin,ULONG state,ULONG stage,NTSTATUS status,ULONG flags)
{
    ULONG i,slot=ST_NEG_CAPACITY;
    for(i=0;i<ST_NEG_CAPACITY;i++){
        if(StNegatives[i].File==file)return FALSE; // Never replace first terminal evidence.
        if(!StNegatives[i].File&&slot==ST_NEG_CAPACITY)slot=i;
    }
    if(!StEnabled||slot==ST_NEG_CAPACITY||StNegativeNext==MAXULONGLONG){
        if(StNegativeGapCount!=MAXULONGLONG)StNegativeGapCount++;
        StNegativeGapQpc=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;return FALSE;
    }
    StNegatives[slot].File=file;StNegatives[slot].Id=++StNegativeNext;
    StNegatives[slot].Deadline=KeQueryInterruptTime()+30ULL*10000000ULL;
    StNegatives[slot].OriginCandidate=origin;StNegatives[slot].State=state;
    StNegatives[slot].Stage=stage;StNegatives[slot].Status=status;StNegatives[slot].Flags=flags;StNegativeReferences++;
    return TRUE;
}
static VOID StNegativeAddFlags(PFILE_OBJECT file,ULONG state,ULONG stage,NTSTATUS status,ULONG flags)
{
    KIRQL old;BOOLEAN transferred;
    if(!file||KeGetCurrentIrql()>APC_LEVEL)return;
    if(!NT_SUCCESS(ObReferenceObjectByPointer(file,0,*IoFileObjectType,KernelMode)))return;
    KeAcquireSpinLock(&StLock,&old);transferred=StNegativeStoreLocked(file,0,state,stage,status,flags);KeReleaseSpinLock(&StLock,old);
    if(!transferred)ObDereferenceObjectDeferDelete(file);
}
static VOID StNegativeAdd(PFILE_OBJECT file,ULONG state,ULONG stage,NTSTATUS status)
{StNegativeAddFlags(file,state,stage,status,0);}
static VOID StNegativeSweep(BOOLEAN all,PFILE_OBJECT cleanup)
{
    ULONG i;KIRQL old;ULONGLONG now=KeQueryInterruptTime();
    for(i=0;i<ST_NEG_CAPACITY;i++){
        PFILE_OBJECT release=NULL;KeAcquireSpinLock(&StLock,&old);
        if(StNegatives[i].File&&(all||(cleanup?StNegatives[i].File==cleanup:StNegatives[i].Deadline<=now))){
            release=StNegatives[i].File;RtlZeroMemory(&StNegatives[i],sizeof(ST_NEG_ASSOC));StNegativeReleased++;
        }
        KeReleaseSpinLock(&StLock,old);if(release)ObDereferenceObjectDeferDelete(release);
    }
}
static VOID StNegativeBind(PEPROCESS process,HANDLE pid,ULONGLONG created,PPS_CREATE_NOTIFY_INFO info)
{
    ULONG i;KIRQL old;PFILE_OBJECT release=NULL;
    KeAcquireSpinLock(&StLock,&old);
    if(StEnabled)for(i=0;i<ST_NEG_CAPACITY;i++){
        ST_NEG_ASSOC* e=&StNegatives[i];ULONGLONG generation;
        if(e->File!=info->FileObject||e->BindAttempted||e->Deadline<=KeQueryInterruptTime())continue;
        e->BindAttempted=TRUE;
        generation=SbBind(process,pid,created,0);
        if(generation){
            SbAcquisitionSet(generation,e->State,e->Stage,e->Status,e->Id,e->OriginCandidate,e->Flags);
            release=e->File;RtlZeroMemory(e,sizeof(*e));StNegativeReleased++;
        }
        break;
    }
    KeReleaseSpinLock(&StLock,old);if(release)ObDereferenceObjectDeferDelete(release);
}
