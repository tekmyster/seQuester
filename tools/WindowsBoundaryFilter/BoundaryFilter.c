#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)

// Qualification fixture only. No automatic volume attachment, no communication
// endpoint, no actor handling. Reject only a single unique test pathname.
static PFLT_FILTER Filter;
static const UNICODE_STRING TestSuffix=RTL_CONSTANT_STRING(L"\\SequesterBoundaryQA-938af2e659ac4e16a01fd60b784687d9\\blocked.bin");
static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
{
    PFLT_FILE_NAME_INFORMATION name=NULL;
    BOOLEAN matches=FALSE;
    UNREFERENCED_PARAMETER(objects);UNREFERENCED_PARAMETER(context);
    if(data->RequestorMode!=UserMode)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if(NT_SUCCESS(FltGetFileNameInformation(data,FLT_FILE_NAME_OPENED|FLT_FILE_NAME_QUERY_DEFAULT,&name))){
        if(name->Name.Length>=TestSuffix.Length){
            UNICODE_STRING tail;
            tail.Length=tail.MaximumLength=TestSuffix.Length;
            tail.Buffer=(PWCHAR)((PUCHAR)name->Name.Buffer+name->Name.Length-TestSuffix.Length);
            matches=RtlEqualUnicodeString(&tail,&TestSuffix,TRUE);
        }
        FltReleaseFileNameInformation(name);
    }
    if(!matches)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    data->IoStatus.Status=STATUS_ACCESS_DENIED;data->IoStatus.Information=0;
    return FLT_PREOP_COMPLETE;
}
static NTSTATUS Setup(PCFLT_RELATED_OBJECTS objects,FLT_INSTANCE_SETUP_FLAGS flags,DEVICE_TYPE device,FLT_FILESYSTEM_TYPE filesystem)
{
    UNREFERENCED_PARAMETER(objects);
    return (flags&FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT)&&device==FILE_DEVICE_DISK_FILE_SYSTEM&&filesystem==FLT_FSTYPE_NTFS?STATUS_SUCCESS:STATUS_FLT_DO_NOT_ATTACH;
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);FltUnregisterFilter(Filter);return STATUS_SUCCESS;
}
static const FLT_OPERATION_REGISTRATION Operations[]={
    {IRP_MJ_CREATE,0,PreCreate,NULL},{IRP_MJ_OPERATION_END}
};
static const FLT_REGISTRATION Registration={sizeof(FLT_REGISTRATION),FLT_REGISTRATION_VERSION,0,NULL,Operations,Unload,Setup};
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
    NTSTATUS status;UNREFERENCED_PARAMETER(registry);
    status=FltRegisterFilter(driver,&Registration,&Filter);if(!NT_SUCCESS(status))return status;
    status=FltStartFiltering(Filter);if(!NT_SUCCESS(status))FltUnregisterFilter(Filter);
    return status;
}
