#pragma once
// Creation-notification evidence, never a live-PID/path enrichment fallback.
// Bounded per-process objects are immutable after attachment; queued actor blobs
// retain them independently of process exit, candidate expiry and candidate ACK.
#define PM_TAG 'mSqS'
#define PM_CAPACITY 256
#define PM_COMMAND_CHARS 2048
#define PM_IMAGE_CHARS 512
typedef struct _PM_DATA {
    ULONG Version,Size,CaptureStatus,Flags;
    ULONGLONG ParentPid,CreatorPid,CreatorTid,CreatorCreated,ParentCreated,CapturedUtc,Monotonic;
    ULONG CreatorStatus,CreationStatus,CommandState,CommandOriginalBytes,CommandBytes,ImageState,ImageOriginalBytes,ImageBytes;
    WCHAR Command[PM_COMMAND_CHARS],Image[PM_IMAGE_CHARS];
} PM_DATA;
C_ASSERT(sizeof(PM_DATA)==5224);
C_ASSERT(FIELD_OFFSET(PM_DATA,Command)==104);
typedef struct _PM_OBJECT {volatile LONG References;PM_DATA Data;} PM_OBJECT;
static volatile LONG PmLive;
static volatile LONG64 PmAllocated,PmFreed,PmRefused;
static VOID PmRelease(PM_OBJECT* value)
{
    if(value&&InterlockedDecrement(&value->References)==0){
        RtlSecureZeroMemory(value,sizeof(*value));ExFreePoolWithTag(value,PM_TAG);InterlockedIncrement64(&PmFreed);InterlockedDecrement(&PmLive);
    }
}
static VOID PmReference(PM_OBJECT* value){if(value)InterlockedIncrement(&value->References);}
// State: 0 absent, 1 complete, 2 truncated, 3 invalid. Keep raw UTF-16;
// managed display validation must not turn malformed text into fabricated text.
static VOID PmString(PCUNICODE_STRING source,PWCHAR output,ULONG capacity,PULONG state,PULONG original,PULONG stored)
{
    ULONG bytes;
    if(!source)return;
    *original=source->Length;
    if((source->Length&1)||source->Length>source->MaximumLength||(!source->Buffer&&source->Length)){*state=3;return;}
    bytes=min(source->Length,capacity*sizeof(WCHAR));
    if(bytes<source->Length&&bytes&&source->Buffer[bytes/2-1]>=0xD800&&source->Buffer[bytes/2-1]<=0xDBFF)bytes-=2;
    if(bytes)RtlCopyMemory(output,source->Buffer,bytes);
    *stored=bytes;*state=bytes<source->Length?2:1;
}
// Called only for a matched candidate, outside every spin lock. No file I/O,
// account resolution, IPC, waiting or large stack allocation occurs here.
// Per-key outcome: 1 complete, 2 object-cap refusal, 3 pool allocation failure.
static PM_OBJECT* PmCapture(PPS_CREATE_NOTIFY_INFO info,PULONG outcome
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    ,ULONG faultMode
#endif
)
{
    PM_OBJECT* value;PM_DATA* data;PEPROCESS creator=NULL;NTSTATUS status;
    LONG capacity=PM_CAPACITY;
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    if(faultMode==CF_CAPACITY_TWO)capacity=2;
#endif
    *outcome=3;
    if(InterlockedIncrement(&PmLive)>capacity){*outcome=2;InterlockedDecrement(&PmLive);InterlockedIncrement64(&PmRefused);return NULL;}
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
    if(faultMode==CF_ALLOCATION_FAILURE)value=NULL;else
#endif
#pragma warning(suppress:4996)
    value=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*value),PM_TAG);
    if(!value){InterlockedDecrement(&PmLive);InterlockedIncrement64(&PmRefused);return NULL;}
    InterlockedIncrement64(&PmAllocated);
    RtlZeroMemory(value,sizeof(*value));value->References=1;data=&value->Data;
    data->Version=1;data->Size=sizeof(*data);*outcome=1;
    data->ParentPid=(ULONGLONG)info->ParentProcessId;
    data->CreatorPid=(ULONGLONG)info->CreatingThreadId.UniqueProcess;data->CreatorTid=(ULONGLONG)info->CreatingThreadId.UniqueThread;
    data->CreationStatus=(ULONG)info->CreationStatus;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&data->CapturedUtc);data->Monotonic=(ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    if(info->FileOpenNameAvailable)data->Flags|=1;
    PmString(info->CommandLine,data->Command,PM_COMMAND_CHARS,&data->CommandState,&data->CommandOriginalBytes,&data->CommandBytes);
    PmString(info->ImageFileName,data->Image,PM_IMAGE_CHARS,&data->ImageState,&data->ImageOriginalBytes,&data->ImageBytes);
    // The create callback runs in the creating thread. PsGetCurrentProcess()
    // can instead be an attached process; validate the owning PID/TID explicitly.
    // Flags bit 1 also means the lookup was attempted. With it clear the raw
    // status remains zero/reserved and user mode reports a null lookup code.
    if(info->CreatingThreadId.UniqueProcess==PsGetCurrentProcessId()&&info->CreatingThreadId.UniqueThread==PsGetCurrentThreadId()
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
       &&faultMode!=CF_MISMATCH
#endif
    ){
        data->Flags|=2;
#ifdef SQ_CREATION_FAULT_DIAGNOSTIC
        if(faultMode==CF_LOOKUP_FAILURE)status=STATUS_ACCESS_DENIED;else
#endif
        status=PsLookupProcessByProcessId(info->CreatingThreadId.UniqueProcess,&creator);data->CreatorStatus=(ULONG)status;
        if(NT_SUCCESS(status)){
            data->CreatorCreated=(ULONGLONG)PsGetProcessCreateTimeQuadPart(creator);
            if(info->ParentProcessId==info->CreatingThreadId.UniqueProcess&&data->CreatorCreated){data->ParentCreated=data->CreatorCreated;data->Flags|=4;}
            ObDereferenceObject(creator);
        }
    }
    return value;
}
