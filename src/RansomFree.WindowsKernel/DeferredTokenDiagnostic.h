#pragma once
// Private qualification only. No production capability advertisement yet.
// All pending records count against the existing global allocation bound.
static LIST_ENTRY DeferredQueue;
static KSPIN_LOCK DeferredLock;
static KEVENT DeferredWake;
static HANDLE DeferredWorker;
static BOOLEAN DeferredStopping;

static VOID DeferredReference(PFLT_CALLBACK_DATA data,SQ_RECORD* record)
{
    SQ_DEFERRED_TOKEN_CONTEXT* evidence=&record->Deferred;
    BOOLEAN copyOnOpen=FALSE,effectiveOnly=FALSE;
    SECURITY_IMPERSONATION_LEVEL level=SecurityAnonymous;
    evidence->Version=1;evidence->Size=sizeof(*evidence);
    evidence->Instance=record->Event.Instance;evidence->Sequence=record->Event.Sequence;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&evidence->ReferencedUtc);
    evidence->ReferenceIrql=KeGetCurrentIrql();evidence->MetadataTiming=1;
    evidence->EntryImpersonationLevel=0xffffffff;
    evidence->CollectionStatus=STATUS_PENDING;
    CaptureToken(NULL,&evidence->ThreadEffective);
    CaptureToken(NULL,&evidence->ThreadOwnerPrimary);
    CaptureToken(NULL,&evidence->RequestorPrimary);
    record->DeferredRequestor=FltGetRequestorProcess(data);
    if(record->DeferredRequestor)ObReferenceObject(record->DeferredRequestor);
    if(data->Thread){
        record->DeferredOwner=IoThreadToProcess(data->Thread);
        if(record->DeferredOwner){ObReferenceObject(record->DeferredOwner);evidence->ThreadProcessCreatedUtc=PsGetProcessCreateTimeQuadPart(record->DeferredOwner);}
        record->DeferredToken=PsReferenceImpersonationToken(data->Thread,&copyOnOpen,&effectiveOnly,&level);
        evidence->Impersonation=record->DeferredToken?2:1;
        if(record->DeferredToken){evidence->CopyOnOpen=copyOnOpen?2:1;evidence->EffectiveOnly=effectiveOnly?2:1;evidence->EntryImpersonationLevel=level;}
    }
}

static VOID DeferredSubmit(SQ_RECORD* record)
{
    KIRQL old;
    KeAcquireSpinLock(&DeferredLock,&old);
    InsertTailList(&DeferredQueue,&record->Link);
    KeReleaseSpinLock(&DeferredLock,old);
    KeSetEvent(&DeferredWake,IO_NO_INCREMENT,FALSE);
}

static VOID DeferredEnrich(SQ_RECORD* record)
{
    SQ_DEFERRED_TOKEN_CONTEXT* evidence=&record->Deferred;
    // Worker is PASSIVE. Never release the last token/process reference at APC.
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&evidence->QueriedUtc);
    if(record->DeferredToken){
        CaptureToken(record->DeferredToken,&evidence->ThreadEffective);
        PsDereferenceImpersonationToken(record->DeferredToken);record->DeferredToken=NULL;
    }
    if(record->DeferredOwner){
        PACCESS_TOKEN token=PsReferencePrimaryToken(record->DeferredOwner);
        CaptureToken(token,&evidence->ThreadOwnerPrimary);PsDereferencePrimaryToken(token);
        ObDereferenceObject(record->DeferredOwner);record->DeferredOwner=NULL;
    }
    if(record->DeferredRequestor){
        PUNICODE_STRING image=NULL;
        PACCESS_TOKEN token=PsReferencePrimaryToken(record->DeferredRequestor);
        CaptureToken(token,&evidence->RequestorPrimary);PsDereferencePrimaryToken(token);
        if(NT_SUCCESS(SeLocateProcessImageName(record->DeferredRequestor,&image))){
            ULONG flags=0;CopyText(evidence->Image,image,&flags);ExFreePool(image);
        }
        ObDereferenceObject(record->DeferredRequestor);record->DeferredRequestor=NULL;
    }
    // No impersonation at entry is an observation. Later primary metadata is
    // NOT copied into an invented entry-time effective-token snapshot.
    evidence->CollectionStatus=evidence->Impersonation==0?STATUS_NOT_FOUND:
        (evidence->Impersonation==2&&evidence->ThreadEffective.Captured!=31)||
        evidence->ThreadOwnerPrimary.Captured!=31||evidence->RequestorPrimary.Captured!=31||
        !evidence->Image[0]?STATUS_PARTIAL_COPY:STATUS_SUCCESS;
}

static VOID DeferredRun(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    for(;;){
        SQ_RECORD* record=NULL;BOOLEAN stop;KIRQL old;
        KeWaitForSingleObject(&DeferredWake,Executive,KernelMode,FALSE,NULL);
        KeAcquireSpinLock(&DeferredLock,&old);
        if(!IsListEmpty(&DeferredQueue))record=CONTAINING_RECORD(RemoveHeadList(&DeferredQueue),SQ_RECORD,Link);
        stop=DeferredStopping;
        if(IsListEmpty(&DeferredQueue)&&!stop)KeClearEvent(&DeferredWake);
        KeReleaseSpinLock(&DeferredLock,old);
        if(record){DeferredEnrich(record);Enqueue(record);continue;}
        if(stop)break;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS DeferredStart(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    InitializeListHead(&DeferredQueue);KeInitializeSpinLock(&DeferredLock);
    KeInitializeEvent(&DeferredWake,NotificationEvent,FALSE);DeferredStopping=FALSE;
    InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
    return PsCreateSystemThread(&DeferredWorker,SYNCHRONIZE,&attributes,NULL,NULL,DeferredRun,NULL);
}

static VOID DeferredStop(VOID)
{
    KIRQL old;
    if(!DeferredWorker)return;
    // Caller unregisters the filter first, so no new callback can submit work.
    KeAcquireSpinLock(&DeferredLock,&old);DeferredStopping=TRUE;KeReleaseSpinLock(&DeferredLock,old);
    KeSetEvent(&DeferredWake,IO_NO_INCREMENT,FALSE);
    ZwWaitForSingleObject(DeferredWorker,FALSE,NULL);ZwClose(DeferredWorker);DeferredWorker=NULL;
}
