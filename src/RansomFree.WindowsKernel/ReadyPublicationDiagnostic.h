#pragma once
// Included after staging state declarations. Every function uses StLock for
// publication metadata only. This feed owns no process/file/blob references.
// Candidate IDs and process generations never repeat within the provider epoch.
#define ST_READY_CAPACITY 256u
#define ST_READY_PAGE_ENTRIES 16u
typedef struct _ST_READY_ROW {
    ULONGLONG Sequence,Generation,Id,Pid,Created,Deadline;
    ULONG ByteLength,State,OriginalAccess,MappedAccess,QualificationVersion,CreateStatus;
    ULONGLONG FileIndex;
} ST_READY_ROW;
C_ASSERT(sizeof(ST_READY_ROW)==80);
typedef struct _ST_READY_REQUEST {
    ULONG Version,Command;
    UUID Provider;
    ULONGLONG AfterSequence;
    ULONG MaximumEntries,Schema;
} ST_READY_REQUEST;
C_ASSERT(sizeof(ST_READY_REQUEST)==40);
typedef struct _ST_READY_PAGE {
    ULONG Version,Size;
    UUID Provider;
    ULONG ProviderStatus,Flags;
    ULONGLONG OperationInstance,OldestRetained,HighestPublished,NextSequence;
    ULONG Count,Capacity;
    ST_READY_ROW Rows[ST_READY_PAGE_ENTRIES];
} ST_READY_PAGE;
C_ASSERT(sizeof(ST_READY_PAGE)==1352);
static ST_READY_ROW StReadyRows[ST_READY_CAPACITY];
static ULONGLONG StReadyHighest;
static BOOLEAN StReadySaturated;

// StLock held. Readiness order differs from candidate admission order.
static VOID StReadyPublish(ST_ENTRY* entry)
{
    ST_READY_ROW* row;
    if(!StEnabled||!entry->Blob||!entry->ProcessGeneration||entry->ReadySequence)return;
    if(StReadyHighest==MAXULONGLONG){StReadySaturated=TRUE;return;}
    entry->ReadySequence=++StReadyHighest;
    row=&StReadyRows[(entry->ReadySequence-1)%ST_READY_CAPACITY];RtlZeroMemory(row,sizeof(*row));
    row->Sequence=entry->ReadySequence;row->Generation=entry->ProcessGeneration;row->Id=entry->Id;
    row->Pid=entry->Pid;row->Created=entry->Created;row->Deadline=entry->Deadline;
    row->ByteLength=entry->Blob->Length;row->State=1;
    row->OriginalAccess=entry->Blob->OriginalRequestedAccess;row->MappedAccess=entry->Blob->RequestedAccess;
    row->QualificationVersion=entry->Blob->QualificationVersion;row->CreateStatus=entry->Blob->CreateStatus;row->FileIndex=entry->Blob->FileId;
}

// States: 1 retrievable at enumeration; 2 expired; 3 acknowledged; 4 detached
// for an unclassified reason; 5 provider stopped. A page is discovery only:
// every subsequent byte request still validates the complete immutable key.
static NTSTATUS StReadyPage(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned,ULONGLONG instance)
{
    ST_READY_REQUEST request;ST_READY_PAGE* page;KIRQL old;ULONGLONG cursor,now;ULONG i;
    NTSTATUS status=STATUS_SUCCESS;
    if(inputBytes!=sizeof(request)||!output||outputBytes<sizeof(ST_READY_PAGE))return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&request,input,sizeof(request));
    if(request.Version!=4||request.Command!=25||request.Schema!=1||!request.MaximumEntries||request.MaximumEntries>ST_READY_PAGE_ENTRIES)return STATUS_INVALID_PARAMETER;
    if(!RtlEqualMemory(&request.Provider,&SbHealth.Provider,sizeof(UUID)))return STATUS_NOT_FOUND;
#pragma warning(suppress:4996)
    page=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*page),ST_TAG);if(!page)return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(page,sizeof(*page));page->Version=1;page->Size=sizeof(*page);page->Provider=SbHealth.Provider;
    page->ProviderStatus=SbHealth.ProviderStatus;page->OperationInstance=instance;page->Capacity=ST_READY_CAPACITY;
    __try{
        KeAcquireSpinLock(&StLock,&old);now=KeQueryInterruptTime();
        page->HighestPublished=StReadyHighest;page->OldestRetained=StReadyHighest>=ST_READY_CAPACITY?StReadyHighest-ST_READY_CAPACITY+1:1;
        if(!StEnabled)page->Flags|=2;if(StReadySaturated)page->Flags|=4;
        if(request.AfterSequence>StReadyHighest){status=STATUS_INVALID_PARAMETER;}
        else if(request.AfterSequence<page->OldestRetained-1){page->Flags|=1;page->NextSequence=page->OldestRetained-1;}
        else{
            cursor=request.AfterSequence;
            while(cursor<StReadyHighest&&page->Count<request.MaximumEntries){
                ST_READY_ROW* row=&page->Rows[page->Count++];cursor++;
                *row=StReadyRows[(cursor-1)%ST_READY_CAPACITY];
                if(row->Sequence!=cursor){status=STATUS_DATA_ERROR;break;}
                row->State=4;
                if(!StEnabled)row->State=5;
                else{
                    for(i=0;i<ST_SLOTS;i++)if(StEntries[i].ReadySequence==cursor&&StEntries[i].Blob&&StEntries[i].Deadline>now){row->State=1;break;}
                    if(row->State!=1){
                        for(i=0;i<ST_ACK_CAPACITY;i++)if(StAcknowledgements[i].Deadline>now&&StAcknowledgements[i].Claim.Key.Id==row->Id&&StAcknowledgements[i].Claim.Key.Generation==row->Generation&&StAcknowledgements[i].Claim.Key.Pid==row->Pid&&StAcknowledgements[i].Claim.Key.Created==row->Created){row->State=3;break;}
                        if(row->State==4&&row->Deadline<=now)row->State=2;
                    }
                }
            }
            page->NextSequence=cursor;
        }
        KeReleaseSpinLock(&StLock,old);
        if(NT_SUCCESS(status)){RtlCopyMemory(output,page,sizeof(*page));*returned=sizeof(*page);}
    }__finally{ExFreePoolWithTag(page,ST_TAG);}
    return status;
}
