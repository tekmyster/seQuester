#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)

// Read-only qualification probe: refuses every instance and registers no I/O
// callbacks. Records the actual InstanceSetup properties rather than guessing
// a redirector type from a volume's displayed name.
#define SQ_MAX_VOLUMES 64
#define SQ_NAME_CHARS 192
typedef struct _SQ_VOLUME {
    ULONG DeviceType, FileSystemType;
    NTSTATUS PropertiesStatus, VolumeNameStatus;
    WCHAR VolumeName[SQ_NAME_CHARS], DriverName[SQ_NAME_CHARS];
    WCHAR DeviceName[SQ_NAME_CHARS], RealDeviceName[SQ_NAME_CHARS];
} SQ_VOLUME;
#ifdef SQ_SMB_ROUTING_PROBE
typedef struct _SQ_OPERATION {
    ULONG Major, Flags; ULONG_PTR Pid, Tid; LONGLONG ProcessStart;
    NTSTATUS Status; ULONG Reserved; ULONG_PTR Information; WCHAR Name[768];
} SQ_OPERATION;
typedef struct _SQ_REPORT {ULONG Version, Count, Dropped, OperationCount, OperationDropped, Reserved; SQ_VOLUME Volumes[SQ_MAX_VOLUMES];SQ_OPERATION Operations[64];} SQ_REPORT;
#else
typedef struct _SQ_REPORT {ULONG Version, Count, Dropped; SQ_VOLUME Volumes[SQ_MAX_VOLUMES];} SQ_REPORT;
#endif
static SQ_REPORT Report;
static KSPIN_LOCK ReportLock;
static PFLT_FILTER Filter;
static PFLT_PORT ServerPort, ClientPort;
static VOID CopyName(PWCHAR target, PCUNICODE_STRING source)
{
    USHORT bytes=(USHORT)min(source->Length,(SQ_NAME_CHARS-1)*sizeof(WCHAR));
    if(bytes&&source->Buffer)RtlCopyMemory(target,source->Buffer,bytes);
}
static NTSTATUS Setup(PCFLT_RELATED_OBJECTS objects,FLT_INSTANCE_SETUP_FLAGS flags,DEVICE_TYPE device,FLT_FILESYSTEM_TYPE filesystem)
{
    SQ_VOLUME record; PFLT_VOLUME_PROPERTIES properties; ULONG bytes=0; KIRQL oldIrql;
    UNICODE_STRING name; UNREFERENCED_PARAMETER(flags);
    RtlZeroMemory(&record,sizeof(record));record.DeviceType=device;record.FileSystemType=filesystem;
    if(KeGetCurrentIrql()>APC_LEVEL){record.PropertiesStatus=STATUS_INVALID_DEVICE_STATE;record.VolumeNameStatus=STATUS_INVALID_DEVICE_STATE;}
    else {
        name.Buffer=record.VolumeName;name.Length=0;name.MaximumLength=sizeof(record.VolumeName)-sizeof(WCHAR);
        record.VolumeNameStatus=FltGetVolumeName(objects->Volume,&name,NULL);
#pragma warning(suppress:4996) // Retain Server 2012 R2 support; ExAllocatePool2 is unavailable there.
        properties=ExAllocatePoolWithTag(PagedPool,8192,'vQSS');
        if(!properties)record.PropertiesStatus=STATUS_INSUFFICIENT_RESOURCES;
        else {
            record.PropertiesStatus=FltGetVolumeProperties(objects->Volume,properties,8192,&bytes);
            if(NT_SUCCESS(record.PropertiesStatus)){
                CopyName(record.DriverName,&properties->FileSystemDriverName);
                CopyName(record.DeviceName,&properties->FileSystemDeviceName);
                CopyName(record.RealDeviceName,&properties->RealDeviceName);
            }
            ExFreePoolWithTag(properties,'vQSS');
        }
    }
    KeAcquireSpinLock(&ReportLock,&oldIrql);
    if(Report.Count<SQ_MAX_VOLUMES)Report.Volumes[Report.Count++]=record;else Report.Dropped++;
    KeReleaseSpinLock(&ReportLock,oldIrql);
#ifdef SQ_SMB_ROUTING_PROBE
    // Qualification candidate only: actual tuple observed on all four hosts.
    // No production attribution claim until callbacks and local actors qualify.
    if(device==FILE_DEVICE_NETWORK_FILE_SYSTEM&&filesystem==FLT_FSTYPE_MUP&&NT_SUCCESS(record.PropertiesStatus)){
        UNICODE_STRING actual,expected=RTL_CONSTANT_STRING(L"\\FileSystem\\Mup");
        RtlInitUnicodeString(&actual,record.DriverName);
        if(RtlEqualUnicodeString(&actual,&expected,TRUE))return STATUS_SUCCESS;
    }
#endif
    return STATUS_FLT_DO_NOT_ATTACH;
}
#ifdef SQ_SMB_ROUTING_PROBE
#ifdef SQ_SMB_NAME_PROBE
// Diagnostic only: bounded comparison against the two uniquely owned shares.
// Raw FILE_OBJECT names are logged as raw, never promoted to normalized paths.
static BOOLEAN HasOwnedShare(PCUNICODE_STRING value,PCUNICODE_STRING share)
{
    USHORT offset;
    if(!value||!value->Buffer||value->Length>8192||value->Length<share->Length)return FALSE;
    for(offset=0;offset<=value->Length-share->Length;offset+=sizeof(WCHAR)){
        UNICODE_STRING part;part.Length=part.MaximumLength=share->Length;
        part.Buffer=(PWCHAR)((PUCHAR)value->Buffer+offset);
        if(RtlEqualUnicodeString(&part,share,TRUE))return TRUE;
    }
    return FALSE;
}
#endif
static FLT_PREOP_CALLBACK_STATUS ObservePre(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
{
    PFLT_FILE_NAME_INFORMATION name=NULL;SQ_OPERATION* record;PEPROCESS process;
    UNICODE_STRING full=RTL_CONSTANT_STRING(L"SequesterQAFull-df435a2b8a69");
    UNICODE_STRING read=RTL_CONSTANT_STRING(L"SequesterQARead-df435a2b8a69");
    NTSTATUS status;UNREFERENCED_PARAMETER(objects);*context=NULL;
#ifndef SQ_SMB_NAME_PROBE
    UNICODE_STRING tail;
#endif
    if(KeGetCurrentIrql()>APC_LEVEL||data->RequestorMode!=UserMode)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status=FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_DEFAULT,&name);
#ifdef SQ_SMB_NAME_PROBE
    {
        PCUNICODE_STRING observed=NT_SUCCESS(status)?&name->Name:objects->FileObject?&objects->FileObject->FileName:NULL;
        if(!HasOwnedShare(observed,&full)&&!HasOwnedShare(observed,&read)){if(name)FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
#pragma warning(suppress:4996)
        record=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*record),'oQSS');
        if(!record){if(name)FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
        RtlZeroMemory(record,sizeof(*record));record->Major=data->Iopb->MajorFunction;record->Flags=data->Flags;
        if(!NT_SUCCESS(status))record->Flags|=0x80000000u;
        if(objects->FileObject&&objects->FileObject->RelatedFileObject)record->Flags|=0x40000000u;
        record->Reserved=(ULONG)status;
        record->Pid=(ULONG_PTR)FltGetRequestorProcessId(data);record->Tid=data->Thread?(ULONG_PTR)PsGetThreadId(data->Thread):0;
        process=FltGetRequestorProcess(data);record->ProcessStart=process?PsGetProcessCreateTimeQuadPart(process):0;
        RtlCopyMemory(record->Name,observed->Buffer,min(observed->Length,sizeof(record->Name)-sizeof(WCHAR)));
        if(name)FltReleaseFileNameInformation(name);*context=record;return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
#else
    if(!NT_SUCCESS(status))return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status=FltParseFileNameInformation(name);
    if(!NT_SUCCESS(status)||name->Share.Length<full.Length){FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    // Parse Share can include the server prefix. Compare the full terminal share
    // component and require a separator immediately before it.
    tail.Length=tail.MaximumLength=full.Length;tail.Buffer=(PWCHAR)((PUCHAR)name->Share.Buffer+name->Share.Length-full.Length);
    if(!RtlEqualUnicodeString(&tail,&full,TRUE)&&!RtlEqualUnicodeString(&tail,&read,TRUE)){
        FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if(name->Share.Length>tail.Length&&tail.Buffer[-1]!=L'\\'){FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
#pragma warning(suppress:4996)
    record=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(*record),'oQSS');
    if(!record){FltReleaseFileNameInformation(name);return FLT_PREOP_SUCCESS_NO_CALLBACK;}
    RtlZeroMemory(record,sizeof(*record));record->Major=data->Iopb->MajorFunction;record->Flags=data->Flags;
    record->Pid=(ULONG_PTR)FltGetRequestorProcessId(data);record->Tid=data->Thread?(ULONG_PTR)PsGetThreadId(data->Thread):0;
    process=FltGetRequestorProcess(data);record->ProcessStart=process?PsGetProcessCreateTimeQuadPart(process):0;
    RtlCopyMemory(record->Name,name->Name.Buffer,min(name->Name.Length,sizeof(record->Name)-sizeof(WCHAR)));
    FltReleaseFileNameInformation(name);*context=record;return FLT_PREOP_SUCCESS_WITH_CALLBACK;
#endif
}
static FLT_POSTOP_CALLBACK_STATUS ObservePost(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID context,FLT_POST_OPERATION_FLAGS flags)
{
    SQ_OPERATION* record=context;KIRQL oldIrql;UNREFERENCED_PARAMETER(objects);
    if(!record)return FLT_POSTOP_FINISHED_PROCESSING;
    if(!(flags&FLTFL_POST_OPERATION_DRAINING)){
        record->Status=data->IoStatus.Status;record->Information=data->IoStatus.Information;
        KeAcquireSpinLock(&ReportLock,&oldIrql);
        if(Report.OperationCount<64)Report.Operations[Report.OperationCount++]=*record;else Report.OperationDropped++;
        KeReleaseSpinLock(&ReportLock,oldIrql);
    }
    ExFreePoolWithTag(record,'oQSS');return FLT_POSTOP_FINISHED_PROCESSING;
}
#endif
static NTSTATUS Connect(PFLT_PORT port,PVOID cookie,PVOID buffer,ULONG bytes,PVOID* context)
{
    UNREFERENCED_PARAMETER(cookie);UNREFERENCED_PARAMETER(buffer);UNREFERENCED_PARAMETER(bytes);UNREFERENCED_PARAMETER(context);
    ClientPort=port;return STATUS_SUCCESS;
}
static VOID Disconnect(PVOID cookie){UNREFERENCED_PARAMETER(cookie);FltCloseClientPort(Filter,&ClientPort);}
static NTSTATUS Message(PVOID cookie,PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned)
{
    KIRQL oldIrql;SQ_REPORT* snapshot;UNREFERENCED_PARAMETER(cookie);UNREFERENCED_PARAMETER(input);UNREFERENCED_PARAMETER(inputBytes);
    *returned=0;if(outputBytes<sizeof(Report))return STATUS_BUFFER_TOO_SMALL;
#pragma warning(suppress:4996) // Retain the API available on every qualification host.
    snapshot=ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(Report),'vQSS');if(!snapshot)return STATUS_INSUFFICIENT_RESOURCES;
    KeAcquireSpinLock(&ReportLock,&oldIrql);RtlCopyMemory(snapshot,&Report,sizeof(Report));KeReleaseSpinLock(&ReportLock,oldIrql);
    RtlCopyMemory(output,snapshot,sizeof(Report));ExFreePoolWithTag(snapshot,'vQSS');
    *returned=sizeof(Report);return STATUS_SUCCESS;
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);FltCloseCommunicationPort(ServerPort);FltUnregisterFilter(Filter);return STATUS_SUCCESS;
}
static const FLT_OPERATION_REGISTRATION Operations[]={
#ifdef SQ_SMB_ROUTING_PROBE
    {IRP_MJ_CREATE,0,ObservePre,ObservePost},{IRP_MJ_READ,0,ObservePre,ObservePost},
    {IRP_MJ_WRITE,0,ObservePre,ObservePost},{IRP_MJ_SET_INFORMATION,0,ObservePre,ObservePost},
#endif
    {IRP_MJ_OPERATION_END}};
static const FLT_REGISTRATION Registration={sizeof(FLT_REGISTRATION),FLT_REGISTRATION_VERSION,0,NULL,Operations,Unload,Setup};
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
    NTSTATUS status;PSECURITY_DESCRIPTOR security=NULL;OBJECT_ATTRIBUTES attributes;
#ifdef SQ_SMB_ROUTING_PROBE
    UNICODE_STRING port=RTL_CONSTANT_STRING(L"\\SequesterSmbRoutingQA");
#else
    UNICODE_STRING port=RTL_CONSTANT_STRING(L"\\SequesterVolumeQA");
#endif
    UNREFERENCED_PARAMETER(registry);KeInitializeSpinLock(&ReportLock);
#ifdef SQ_SMB_ROUTING_PROBE
    Report.Version=2;
#else
    Report.Version=1;
#endif
    status=FltRegisterFilter(driver,&Registration,&Filter);if(!NT_SUCCESS(status))return status;
    status=FltBuildDefaultSecurityDescriptor(&security,FLT_PORT_ALL_ACCESS);
    if(!NT_SUCCESS(status)){FltUnregisterFilter(Filter);return status;}
    InitializeObjectAttributes(&attributes,&port,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,security);
    status=FltCreateCommunicationPort(Filter,&ServerPort,&attributes,NULL,Connect,Disconnect,Message,1);
    FltFreeSecurityDescriptor(security);
    if(!NT_SUCCESS(status)){FltUnregisterFilter(Filter);return status;}
    status=FltStartFiltering(Filter);
    if(!NT_SUCCESS(status)){FltCloseCommunicationPort(ServerPort);FltUnregisterFilter(Filter);}
    return status;
}
