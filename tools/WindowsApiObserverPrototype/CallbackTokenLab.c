// Isolated qualification only: one owned thread, one retained token, READ only.
// No arbitrary thread/PID input. Metadata is queried later at PASSIVE and must
// never be described as an immutable operation-time token snapshot.
#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#include <wdmsec.h>
#pragma warning(pop)
#include "CallbackTokenLabProtocol.h"
static PFLT_FILTER Filter;
static PDRIVER_OBJECT Driver;
static UNICODE_STRING Link;
static KSPIN_LOCK Lock;
static PETHREAD ArmedThread;
static PFILE_OBJECT ArmedFile;
static WCHAR ArmedName[260];
static USHORT ArmedNameBytes;
static PETHREAD OwnerThread;
static PACCESS_TOKEN Held;
static SQ_CB_REPLY Snapshot;
static BOOLEAN Busy,Closing;
static ULONG Mode;
static const GUID DeviceClass={0x9e265e0c,0x28fb,0x43d4,{0x86,0xc5,0xe2,0x91,0x23,0x12,0x16,0xc5}};
// Caller holds Lock, at PASSIVE before acquiring it. Remove references under
// the spin lock, release them after restoring PASSIVE; never dereference at APC.
static BOOLEAN Take(PACCESS_TOKEN* token,PETHREAD* thread,PFILE_OBJECT* file)
{
    KIRQL old;BOOLEAN success=FALSE;
    KeAcquireSpinLock(&Lock,&old);
    if(!Busy){*token=Held;*thread=ArmedThread;*file=ArmedFile;Held=NULL;ArmedThread=NULL;ArmedFile=NULL;success=TRUE;}
    else Closing=TRUE;
    KeReleaseSpinLock(&Lock,old);return success;
}
static VOID Release(PACCESS_TOKEN token,PETHREAD thread,PFILE_OBJECT file){if(token)PsDereferenceImpersonationToken(token);if(thread)ObDereferenceObject(thread);if(file)ObDereferenceObject(file);}
static FLT_PREOP_CALLBACK_STATUS Pre(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID* context)
{
    KIRQL old,entry=KeGetCurrentIrql(),raised=PASSIVE_LEVEL;
    BOOLEAN selected=FALSE,copy=FALSE,effective=FALSE,forced=FALSE,sameDevice=FALSE,sameName=FALSE;
    SECURITY_IMPERSONATION_LEVEL level=SecurityAnonymous;PACCESS_TOKEN token;ULONGLONG pid,tid,birth;
    WCHAR callbackName[260];USHORT callbackNameBytes=objects->FileObject?objects->FileObject->FileName.Length:0;BOOLEAN nameCopied=FALSE;
    *context=NULL;
    if(entry>APC_LEVEL)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if(objects->FileObject&&callbackNameBytes&&callbackNameBytes<=sizeof(callbackName)){RtlCopyMemory(callbackName,objects->FileObject->FileName.Buffer,callbackNameBytes);nameCopied=TRUE;}
    KeAcquireSpinLock(&Lock,&old);
    if(ArmedFile&&!Closing){
        Snapshot.ArmedReadCallbacks++;
        sameDevice=objects->FileObject&&ArmedFile->DeviceObject==objects->FileObject->DeviceObject;
        sameName=nameCopied&&ArmedNameBytes==callbackNameBytes&&RtlCompareMemory(ArmedName,callbackName,callbackNameBytes)==callbackNameBytes;
        if(sameDevice&&sameName)Snapshot.TargetNameCallbacks++;
        if(ArmedThread==data->Thread){Snapshot.OwnerReadCallbacks++;Snapshot.LastOwnerSameDevice=sameDevice;Snapshot.LastOwnerSameName=sameName;Snapshot.LastOwnerNameBytes=objects->FileObject?objects->FileObject->FileName.Length:0;Snapshot.ArmedNameBytes=ArmedNameBytes;}
    }
    // Name/device matching is confined to immutable owned test paths; it is not
    // production stable file identity or permission to follow rename races.
    if(ArmedFile&&!Closing&&(ArmedFile==objects->FileObject||(sameDevice&&sameName))){
        Snapshot.TargetCallbacks++;Snapshot.LastCallbackIrql=entry;
        Snapshot.LastCallbackTid=data->Thread?(ULONGLONG)(ULONG_PTR)PsGetThreadId(data->Thread):0;
        if(!data->Thread)Snapshot.NullThreadCallbacks++;
        else if(ArmedThread!=data->Thread)Snapshot.OtherThreadCallbacks++;
        if(data->Thread&&ArmedThread==data->Thread){Snapshot.Callbacks++;if(!Busy&&!Snapshot.Completed&&!Held){Busy=TRUE;selected=TRUE;forced=Mode==1&&entry==PASSIVE_LEVEL;}}
    }
    KeReleaseSpinLock(&Lock,old);
    if(!selected)return FLT_PREOP_SUCCESS_NO_CALLBACK;
    // Busy protects the singleton and its thread reference until post callback.
    if(forced)KeRaiseIrql(APC_LEVEL,&raised);
    token=PsReferenceImpersonationToken(data->Thread,&copy,&effective,&level);
    if(forced)KeLowerIrql(raised);
    pid=FltGetRequestorProcessId(data);tid=(ULONGLONG)(ULONG_PTR)PsGetThreadId(data->Thread);
    birth=FltGetRequestorProcess(data)?PsGetProcessCreateTimeQuadPart(FltGetRequestorProcess(data)):0;
    KeAcquireSpinLock(&Lock,&old);
    Held=token;Snapshot.CallbackIrql=entry;Snapshot.ReferenceIrql=forced?APC_LEVEL:entry;Snapshot.ForcedApc=forced;
    Snapshot.Pid=pid;Snapshot.Tid=tid;Snapshot.ProcessBirth=birth;
    Snapshot.Impersonating=token!=NULL;Snapshot.CopyOnOpen=copy;Snapshot.EffectiveOnly=effective;Snapshot.Level=level;
    KeReleaseSpinLock(&Lock,old);*context=(PVOID)1;return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
static FLT_POSTOP_CALLBACK_STATUS Post(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PVOID context,FLT_POST_OPERATION_FLAGS flags)
{
    KIRQL old;UNREFERENCED_PARAMETER(objects);UNREFERENCED_PARAMETER(flags);
    if(context){KeAcquireSpinLock(&Lock,&old);Snapshot.OperationStatus=data->IoStatus.Status;Snapshot.Completed=1;Busy=FALSE;KeReleaseSpinLock(&Lock,old);}
    return FLT_POSTOP_FINISHED_PROCESSING;
}
static const FLT_OPERATION_REGISTRATION Operations[]={{IRP_MJ_READ,0,Pre,Post},{IRP_MJ_OPERATION_END}};
static NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS flags);
static const FLT_REGISTRATION Registration={sizeof(FLT_REGISTRATION),FLT_REGISTRATION_VERSION,0,NULL,Operations,FilterUnload};
static NTSTATUS Complete(PIRP irp,NTSTATUS status,ULONG size){irp->IoStatus.Status=status;irp->IoStatus.Information=size;IoCompleteRequest(irp,IO_NO_INCREMENT);return status;}
static NTSTATUS Dispatch(PDEVICE_OBJECT device,PIRP irp)
{
    PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);NTSTATUS status=STATUS_SUCCESS;ULONG bytes=0;PACCESS_TOKEN token=NULL;PETHREAD thread=NULL;PFILE_OBJECT file=NULL;KIRQL old;
    UNREFERENCED_PARAMETER(device);
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);
    if(stack->MajorFunction==IRP_MJ_CLEANUP||stack->MajorFunction==IRP_MJ_CLOSE){
        if(Take(&token,&thread,&file)){PETHREAD owner;Release(token,thread,file);KeAcquireSpinLock(&Lock,&old);owner=OwnerThread;OwnerThread=NULL;KeReleaseSpinLock(&Lock,old);if(owner)ObDereferenceObject(owner);}
        return Complete(irp,STATUS_SUCCESS,0);
    }
    if(stack->MajorFunction==IRP_MJ_CREATE){
        thread=PsGetCurrentThread();ObReferenceObject(thread);KeAcquireSpinLock(&Lock,&old);
        if(OwnerThread||Busy){KeReleaseSpinLock(&Lock,old);ObDereferenceObject(thread);return Complete(irp,STATUS_DEVICE_BUSY,0);}
        OwnerThread=thread;KeReleaseSpinLock(&Lock,old);return Complete(irp,STATUS_SUCCESS,0);
    }
    if(stack->MajorFunction!=IRP_MJ_DEVICE_CONTROL)return Complete(irp,STATUS_INVALID_DEVICE_REQUEST,0);
    KeAcquireSpinLock(&Lock,&old);status=OwnerThread==PsGetCurrentThread()?STATUS_SUCCESS:STATUS_ACCESS_DENIED;KeReleaseSpinLock(&Lock,old);
    if(!NT_SUCCESS(status))return Complete(irp,status,0);
    if(stack->Parameters.DeviceIoControl.OutputBufferLength<sizeof(Snapshot))return Complete(irp,STATUS_BUFFER_TOO_SMALL,0);
    if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_CB_ARM){
        SQ_CB_ARM_INPUT input;WCHAR sourceName[260];USHORT sourceNameBytes;
        if(stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(input))return Complete(irp,STATUS_INVALID_PARAMETER,0);
        RtlCopyMemory(&input,irp->AssociatedIrp.SystemBuffer,sizeof(input));if(input.Mode>2||input.Reserved)return Complete(irp,STATUS_INVALID_PARAMETER,0);
        // Retain only the caller's readable file object. This reference is never
        // attached to a handcrafted IRP; release it at PASSIVE after query/close.
        status=ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)input.FileHandle,FILE_READ_DATA,*IoFileObjectType,UserMode,(PVOID*)&file,NULL);
        if(!NT_SUCCESS(status))return Complete(irp,status,0);
        {PFILE_OBJECT previous=NULL;
         if(!Take(&token,&thread,&previous)){ObDereferenceObject(file);return Complete(irp,STATUS_DEVICE_BUSY,0);}
         Release(token,thread,previous);}
        sourceNameBytes=file->FileName.Length;
        if(sourceNameBytes>sizeof(sourceName)){ObDereferenceObject(file);return Complete(irp,STATUS_NAME_TOO_LONG,0);}
        if(sourceNameBytes)RtlCopyMemory(sourceName,file->FileName.Buffer,sourceNameBytes);
        thread=PsGetCurrentThread();ObReferenceObject(thread);
        KeAcquireSpinLock(&Lock,&old);ArmedNameBytes=sourceNameBytes;if(sourceNameBytes)RtlCopyMemory(ArmedName,sourceName,sourceNameBytes);RtlZeroMemory(&Snapshot,sizeof(Snapshot));Snapshot.Version=2;Snapshot.Size=sizeof(Snapshot);ArmedThread=thread;ArmedFile=file;Mode=input.Mode;Closing=FALSE;RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&Snapshot,sizeof(Snapshot));KeReleaseSpinLock(&Lock,old);bytes=sizeof(Snapshot);
    }else if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_CB_PEEK){
        KeAcquireSpinLock(&Lock,&old);RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&Snapshot,sizeof(Snapshot));KeReleaseSpinLock(&Lock,old);bytes=sizeof(Snapshot);
    }else if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_CB_QUERY){
        SQ_CB_REPLY result;PTOKEN_USER user=NULL;PTOKEN_STATISTICS statistics=NULL;
        KeAcquireSpinLock(&Lock,&old);
        if(Busy||!Snapshot.Completed||ArmedThread!=PsGetCurrentThread()){KeReleaseSpinLock(&Lock,old);return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);}
        result=Snapshot;token=Held;Held=NULL;thread=ArmedThread;ArmedThread=NULL;file=ArmedFile;ArmedFile=NULL;
        KeReleaseSpinLock(&Lock,old);
        result.QueryIrql=KeGetCurrentIrql();result.UserStatus=token?SeQueryInformationToken(token,TokenUser,(PVOID*)&user):STATUS_NO_TOKEN;
        result.StatisticsStatus=token?SeQueryInformationToken(token,TokenStatistics,(PVOID*)&statistics):STATUS_NO_TOKEN;
        if(NT_SUCCESS(result.UserStatus)&&user){ULONG length=RtlLengthSid(user->User.Sid);if(length<=sizeof(result.Sid)&&RtlValidSid(user->User.Sid)){result.SidBytes=length;RtlCopyMemory(result.Sid,user->User.Sid,length);}else result.UserStatus=STATUS_INVALID_SID;}
        if(NT_SUCCESS(result.StatisticsStatus)&&statistics){result.TokenId=statistics->TokenId;result.AuthenticationId=statistics->AuthenticationId;result.ModifiedId=statistics->ModifiedId;}
        if(user)ExFreePool(user);if(statistics)ExFreePool(statistics);Release(token,thread,file);
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&result,sizeof(result));bytes=sizeof(result);
    }else status=STATUS_INVALID_DEVICE_REQUEST;
    return Complete(irp,status,bytes);
}
static NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    PACCESS_TOKEN token=NULL;PETHREAD thread=NULL;PFILE_OBJECT file=NULL;UNREFERENCED_PARAMETER(flags);
    FltUnregisterFilter(Filter);if(Take(&token,&thread,&file))Release(token,thread,file);
    if(OwnerThread){ObDereferenceObject(OwnerThread);OwnerThread=NULL;}
    IoDeleteSymbolicLink(&Link);IoDeleteDevice(Driver->DeviceObject);return STATUS_SUCCESS;
}
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
    UNICODE_STRING name,sddl;PDEVICE_OBJECT device=NULL;NTSTATUS status;ULONG i;
    UNREFERENCED_PARAMETER(registry);Driver=driver;KeInitializeSpinLock(&Lock);
    RtlInitUnicodeString(&name,L"\\Device\\SqCallbackTokenLab");RtlInitUnicodeString(&Link,L"\\DosDevices\\SqCallbackTokenLab");RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,TRUE,&sddl,&DeviceClass,&device);if(!NT_SUCCESS(status))return status;
    for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=Dispatch;device->Flags|=DO_BUFFERED_IO;
    status=IoCreateSymbolicLink(&Link,&name);if(!NT_SUCCESS(status)){IoDeleteDevice(device);return status;}
    status=FltRegisterFilter(driver,&Registration,&Filter);if(NT_SUCCESS(status)){status=FltStartFiltering(Filter);if(!NT_SUCCESS(status))FltUnregisterFilter(Filter);}
    if(!NT_SUCCESS(status)){IoDeleteSymbolicLink(&Link);IoDeleteDevice(device);return status;}device->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;
}
