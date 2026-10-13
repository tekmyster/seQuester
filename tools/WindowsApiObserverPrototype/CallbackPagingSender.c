// Isolated read-only qualification sender. Filter Manager owns request creation
// and completion. Caller owns its file reference and nonpaged buffer. The
// callback data owns its associated MDL, as documented for FltFreeCallbackData.
#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#include <wdmsec.h>
#pragma warning(pop)
#include "CallbackTokenLabProtocol.h"
static PFLT_FILTER Sender;
static PDRIVER_OBJECT Driver;
static EX_RUNDOWN_REF Calls;
static UNICODE_STRING Link;
static const GUID DeviceClass={0xa3ffcb51,0x2b30,0x4c07,{0xb7,0x08,0x65,0x74,0xa2,0xca,0x38,0x22}};
static NTSTATUS ReadOwned(ULONGLONG handle,SQ_CB_SENDER_REPLY* reply)
{
 PFILE_OBJECT file=NULL;PFLT_VOLUME volume=NULL;PFLT_INSTANCE instance=NULL;
 PFLT_CALLBACK_DATA data=NULL;PVOID buffer=NULL;PMDL mdl=NULL;NTSTATUS status;KIRQL old;
 FILE_STANDARD_INFORMATION standard;ULONG returned;
 status=ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)handle,FILE_READ_DATA,*IoFileObjectType,UserMode,(PVOID*)&file,NULL);
 if(!NT_SUCCESS(status))goto Exit;
 status=FltGetVolumeFromFileObject(Sender,file,&volume);if(!NT_SUCCESS(status))goto Exit;
 status=FltGetVolumeInstanceFromName(Sender,volume,NULL,&instance);if(!NT_SUCCESS(status))goto Exit;
 status=FltQueryInformationFile(instance,file,&standard,sizeof(standard),FileStandardInformation,&returned);
 if(!NT_SUCCESS(status))goto Exit;
 if(standard.Directory||standard.EndOfFile.QuadPart<4096){status=STATUS_INVALID_PARAMETER;goto Exit;}
 buffer=FltAllocatePoolAlignedWithTag(instance,NonPagedPoolNx,4096,'pCqS');
 if(!buffer){status=STATUS_INSUFFICIENT_RESOURCES;goto Exit;}RtlZeroMemory(buffer,4096);
 mdl=IoAllocateMdl(buffer,4096,FALSE,FALSE,NULL);if(!mdl){status=STATUS_INSUFFICIENT_RESOURCES;goto Exit;}
 MmBuildMdlForNonPagedPool(mdl);
 status=FltAllocateCallbackData(instance,file,&data);if(!NT_SUCCESS(status))goto Exit;
 data->Iopb->MajorFunction=IRP_MJ_READ;data->Iopb->MinorFunction=0;
 data->Iopb->IrpFlags=IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO|IRP_NOCACHE;
 data->Iopb->Parameters.Read.Length=4096;data->Iopb->Parameters.Read.ByteOffset.QuadPart=0;
 data->Iopb->Parameters.Read.ReadBuffer=buffer;data->Iopb->Parameters.Read.MdlAddress=mdl;mdl=NULL;
 // FltPerformSynchronousIo is documented <= APC_LEVEL; FltReadFile's public
 // documentation specifies PASSIVE. All preparation/release remains PASSIVE.
 KeRaiseIrql(APC_LEVEL,&old);reply->SubmitIrql=KeGetCurrentIrql();
 FltPerformSynchronousIo(data);KeLowerIrql(old);
 status=data->IoStatus.Status;reply->OperationStatus=status;reply->BytesRead=data->IoStatus.Information;
 if(NT_SUCCESS(status)&&reply->BytesRead)reply->FirstByte=*(PUCHAR)buffer;
Exit:
 // FltFreeCallbackData frees its associated MDL chain. Never free it twice.
 if(data)FltFreeCallbackData(data);
 if(mdl)IoFreeMdl(mdl);
 if(buffer)FltFreePoolAlignedWithTag(instance,buffer,'pCqS');
 if(instance)FltObjectDereference(instance);if(volume)FltObjectDereference(volume);
 if(file)ObDereferenceObject(file);return status;
}
static NTSTATUS Dispatch(PDEVICE_OBJECT device,PIRP irp)
{
 PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);NTSTATUS status=STATUS_SUCCESS;ULONG size=0;
 BOOLEAN acquired=FALSE;UNREFERENCED_PARAMETER(device);
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)status=STATUS_INVALID_DEVICE_STATE;
 else if(stack->MajorFunction==IRP_MJ_DEVICE_CONTROL){
  acquired=ExAcquireRundownProtection(&Calls);
  if(!acquired)status=STATUS_DELETE_PENDING;
  else if(irp->RequestorMode!=UserMode||stack->Parameters.DeviceIoControl.IoControlCode!=SQ_CB_SENDER_READ||stack->Parameters.DeviceIoControl.InputBufferLength!=sizeof(ULONGLONG)||stack->Parameters.DeviceIoControl.OutputBufferLength<sizeof(SQ_CB_SENDER_REPLY))status=STATUS_INVALID_PARAMETER;
  else{ULONGLONG handle;SQ_CB_SENDER_REPLY result={0};RtlCopyMemory(&handle,irp->AssociatedIrp.SystemBuffer,sizeof(handle));result.Version=1;result.Size=sizeof(result);status=ReadOwned(handle,&result);if(NT_SUCCESS(status)){RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&result,sizeof(result));size=sizeof(result);}}
 }else if(stack->MajorFunction!=IRP_MJ_CREATE&&stack->MajorFunction!=IRP_MJ_CLEANUP&&stack->MajorFunction!=IRP_MJ_CLOSE)status=STATUS_INVALID_DEVICE_REQUEST;
 if(acquired)ExReleaseRundownProtection(&Calls);
 irp->IoStatus.Status=status;irp->IoStatus.Information=size;IoCompleteRequest(irp,IO_NO_INCREMENT);return status;
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags)
{UNREFERENCED_PARAMETER(flags);ExWaitForRundownProtectionRelease(&Calls);FltUnregisterFilter(Sender);IoDeleteSymbolicLink(&Link);IoDeleteDevice(Driver->DeviceObject);return STATUS_SUCCESS;}
static const FLT_OPERATION_REGISTRATION Operations[]={{IRP_MJ_OPERATION_END}};
static const FLT_REGISTRATION Registration={sizeof(FLT_REGISTRATION),FLT_REGISTRATION_VERSION,0,NULL,Operations,Unload};
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
 UNICODE_STRING name,sddl;PDEVICE_OBJECT device;NTSTATUS status;ULONG i;
 UNREFERENCED_PARAMETER(registry);Driver=driver;ExInitializeRundownProtection(&Calls);
 RtlInitUnicodeString(&name,L"\\Device\\SqCallbackPagingSender");RtlInitUnicodeString(&Link,L"\\DosDevices\\SqCallbackPagingSender");RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,TRUE,&sddl,&DeviceClass,&device);if(!NT_SUCCESS(status))return status;
 for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=Dispatch;device->Flags|=DO_BUFFERED_IO;
 status=IoCreateSymbolicLink(&Link,&name);if(!NT_SUCCESS(status)){IoDeleteDevice(device);return status;}
 status=FltRegisterFilter(driver,&Registration,&Sender);if(NT_SUCCESS(status)){status=FltStartFiltering(Sender);if(!NT_SUCCESS(status))FltUnregisterFilter(Sender);}
 if(!NT_SUCCESS(status)){IoDeleteSymbolicLink(&Link);IoDeleteDevice(device);}else device->Flags&=~DO_DEVICE_INITIALIZING;
 return status;
}
