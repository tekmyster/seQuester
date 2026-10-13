// Isolated lab only. Deliberately tests the WDK SAL / Learn IRQL discrepancy.
// No filesystem interception, arbitrary thread input, token query at APC,
// primary-token reference at APC, kernel patching or production integration.
#pragma warning(push)
#pragma warning(disable:4324)
#include <ntifs.h>
#include <wdmsec.h>
#pragma warning(pop)
#include "ApcLabProtocol.h"
static KMUTEX Lock;
static PACCESS_TOKEN Held;
static SQ_LAB_REPLY Snapshot;
static UNICODE_STRING Link;
static const GUID DeviceClass={0xbc3c0d83,0x2c37,0x46ba,{0xb9,0x48,0xad,0xde,0x90,0x55,0x67,0x7a}};
static VOID Release(VOID){if(Held){PsDereferenceImpersonationToken(Held);Held=NULL;}RtlZeroMemory(&Snapshot,sizeof(Snapshot));}
static NTSTATUS Complete(PIRP irp,NTSTATUS status,ULONG bytes){irp->IoStatus.Status=status;irp->IoStatus.Information=bytes;IoCompleteRequest(irp,IO_NO_INCREMENT);return status;}
static NTSTATUS Dispatch(PDEVICE_OBJECT device,PIRP irp)
{
    PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);NTSTATUS status=STATUS_SUCCESS;ULONG bytes=0;
    UNREFERENCED_PARAMETER(device);
    // All lab commands are synchronous calls at PASSIVE. An unexpected elevated
    // cleanup retains the single reference until PASSIVE unload, never frees it
    // at an unsupported level. This is intentionally not a production design.
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);
    status=KeWaitForSingleObject(&Lock,Executive,KernelMode,FALSE,NULL);
    if(!NT_SUCCESS(status))return Complete(irp,status,0);
    switch(stack->MajorFunction){
    case IRP_MJ_CREATE:Release();break;
    case IRP_MJ_CLEANUP:case IRP_MJ_CLOSE:Release();break;
    case IRP_MJ_DEVICE_CONTROL:
        if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_RELEASE){Release();break;}
        if(stack->Parameters.DeviceIoControl.OutputBufferLength<sizeof(Snapshot)){status=STATUS_BUFFER_TOO_SMALL;break;}
        if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_PIN){
            KIRQL old;BOOLEAN copy=FALSE,effective=FALSE;SECURITY_IMPERSONATION_LEVEL level=SecurityAnonymous;
            Release();Snapshot.Version=1;Snapshot.Size=sizeof(Snapshot);
            Snapshot.Pid=(ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();Snapshot.Tid=(ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
            KeRaiseIrql(APC_LEVEL,&old);Snapshot.ReferenceIrql=KeGetCurrentIrql();
            Held=PsReferenceImpersonationToken(PsGetCurrentThread(),&copy,&effective,&level);
            KeLowerIrql(old);
            Snapshot.Impersonating=Held!=NULL;Snapshot.CopyOnOpen=copy;Snapshot.EffectiveOnly=effective;Snapshot.Level=level;
        }else if(stack->Parameters.DeviceIoControl.IoControlCode==SQ_QUERY){
            PTOKEN_USER user=NULL;PTOKEN_STATISTICS statistics=NULL;
            if(Snapshot.Pid!=(ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId()||Snapshot.Tid!=(ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId()){status=STATUS_INVALID_DEVICE_STATE;break;}
            Snapshot.QueryIrql=KeGetCurrentIrql();
            Snapshot.UserStatus=Held?SeQueryInformationToken(Held,TokenUser,(PVOID*)&user):STATUS_NO_TOKEN;
            Snapshot.StatisticsStatus=Held?SeQueryInformationToken(Held,TokenStatistics,(PVOID*)&statistics):STATUS_NO_TOKEN;
            if(NT_SUCCESS(Snapshot.UserStatus)&&user){ULONG length=RtlLengthSid(user->User.Sid);if(length<=sizeof(Snapshot.Sid)){Snapshot.SidBytes=length;RtlCopyMemory(Snapshot.Sid,user->User.Sid,length);}else Snapshot.UserStatus=STATUS_BUFFER_TOO_SMALL;}
            if(NT_SUCCESS(Snapshot.StatisticsStatus)&&statistics){Snapshot.TokenId=statistics->TokenId;Snapshot.AuthenticationId=statistics->AuthenticationId;Snapshot.ModifiedId=statistics->ModifiedId;}
            if(user)ExFreePool(user);if(statistics)ExFreePool(statistics);
        }else{status=STATUS_INVALID_DEVICE_REQUEST;break;}
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&Snapshot,sizeof(Snapshot));bytes=sizeof(Snapshot);break;
    default:status=STATUS_INVALID_DEVICE_REQUEST;break;
    }
    KeReleaseMutex(&Lock,FALSE);return Complete(irp,status,bytes);
}
static VOID Unload(PDRIVER_OBJECT driver){Release();IoDeleteSymbolicLink(&Link);IoDeleteDevice(driver->DeviceObject);}
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry)
{
    UNICODE_STRING name,sddl;PDEVICE_OBJECT device=NULL;NTSTATUS status;ULONG i;
    UNREFERENCED_PARAMETER(registry);KeInitializeMutex(&Lock,0);
    RtlInitUnicodeString(&name,L"\\Device\\SqApcTokenLab");RtlInitUnicodeString(&Link,L"\\DosDevices\\SqApcTokenLab");
    RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,TRUE,&sddl,&DeviceClass,&device);if(!NT_SUCCESS(status))return status;
    for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=Dispatch;
    driver->DriverUnload=Unload;device->Flags|=DO_BUFFERED_IO;
    status=IoCreateSymbolicLink(&Link,&name);if(!NT_SUCCESS(status)){IoDeleteDevice(device);return status;}
    device->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;
}
