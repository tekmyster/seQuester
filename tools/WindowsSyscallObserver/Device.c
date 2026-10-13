#include "Device.h"
#include "Bridge.h"
#include <wdmsec.h>
#ifdef SQ_DTRACE_BACKEND
#include "DTraceAdapter.h"
#endif
static const GUID DeviceClass={0x04d457c6,0x0740,0x4986,{0xb0,0xd3,0xf0,0xa5,0xac,0x48,0x58,0xb9}};
static NTSTATUS Complete(PIRP irp,NTSTATUS status,ULONG bytes)
{
    irp->IoStatus.Status=status;irp->IoStatus.Information=bytes;
    IoCompleteRequest(irp,IO_NO_INCREMENT);return status;
}
static NTSTATUS Dispatch(PDEVICE_OBJECT device,PIRP irp)
{
    PIO_STACK_LOCATION s=IoGetCurrentIrpStackLocation(irp);NTSTATUS status;
    UNREFERENCED_PARAMETER(device);
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);
    if(s->MajorFunction==IRP_MJ_CREATE||s->MajorFunction==IRP_MJ_CLOSE||s->MajorFunction==IRP_MJ_CLEANUP)
        return Complete(irp,STATUS_SUCCESS,0);
    if(s->MajorFunction!=IRP_MJ_DEVICE_CONTROL)return Complete(irp,STATUS_INVALID_DEVICE_REQUEST,0);
    // A device ACL permits SYSTEM/admin only. Never accept arbitrary PID/TID
    // input or handles belonging to a different requestor/process context.
    if(irp->RequestorMode!=UserMode||IoGetRequestorProcess(irp)!=PsGetCurrentProcess())
        return Complete(irp,STATUS_ACCESS_DENIED,0);
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_SOURCE||s->Parameters.DeviceIoControl.IoControlCode==SQ_PEEK||
        s->Parameters.DeviceIoControl.IoControlCode==SQ_ACK||s->Parameters.DeviceIoControl.IoControlCode==SQ_TARGET){
        ULONG bytes=0;
        status=SqSyscallIntake(s->Parameters.DeviceIoControl.IoControlCode,irp->AssociatedIrp.SystemBuffer,
            s->Parameters.DeviceIoControl.InputBufferLength,s->Parameters.DeviceIoControl.OutputBufferLength,&bytes);
        return Complete(irp,status,bytes);
    }
#ifdef SQ_DTRACE_BACKEND
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_DTRACE_ATTACH||
        s->Parameters.DeviceIoControl.IoControlCode==SQ_DTRACE_RESTORE||
        s->Parameters.DeviceIoControl.IoControlCode==SQ_DTRACE_CONTEXT||
        s->Parameters.DeviceIoControl.IoControlCode==SQ_DTRACE_HEALTH){
        ULONG bytes=0;
        status=SqDtraceControl(s->Parameters.DeviceIoControl.IoControlCode,
            irp->AssociatedIrp.SystemBuffer,s->Parameters.DeviceIoControl.InputBufferLength,
            s->Parameters.DeviceIoControl.OutputBufferLength,&bytes);
        return Complete(irp,status,bytes);
    }
#endif
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_ARM){
        SQ_ARM_REQUEST* request=(SQ_ARM_REQUEST*)irp->AssociatedIrp.SystemBuffer;
        HANDLE handles[SQ_SYSCALL_TARGETS];ULONG i;
        if(s->Parameters.DeviceIoControl.InputBufferLength!=sizeof(*request)||!request||
            request->Version!=SQ_SYSCALL_SCHEMA||request->Count==0||request->Count>SQ_SYSCALL_TARGETS)
            return Complete(irp,STATUS_INVALID_PARAMETER,0);
        for(i=0;i<request->Count;i++)handles[i]=(HANDLE)(ULONG_PTR)request->Handles[i];
        return Complete(irp,SqSyscallArmCurrentThread(handles,request->Count),0);
    }
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_DISARM)
        return Complete(irp,SqSyscallDisarmCurrentThread(),0);
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_RECORD){
        if(s->Parameters.DeviceIoControl.OutputBufferLength<sizeof(SQ_SYSCALL_RECORD))
            return Complete(irp,STATUS_BUFFER_TOO_SMALL,0);
        status=SqSyscallReadRecord((SQ_SYSCALL_RECORD*)irp->AssociatedIrp.SystemBuffer);
        return Complete(irp,status,NT_SUCCESS(status)?sizeof(SQ_SYSCALL_RECORD):0);
    }
    if(s->Parameters.DeviceIoControl.IoControlCode==SQ_HEALTH){
        SQ_OBSERVER_HEALTH* h=(SQ_OBSERVER_HEALTH*)irp->AssociatedIrp.SystemBuffer;
        if(s->Parameters.DeviceIoControl.OutputBufferLength<sizeof(*h))
            return Complete(irp,STATUS_BUFFER_TOO_SMALL,0);
        RtlZeroMemory(h,sizeof(*h));h->Version=SQ_SYSCALL_SCHEMA;h->RecordBytes=sizeof(SQ_SYSCALL_RECORD);
        SqSyscallHealth(&h->Observed,&h->Lost,&h->Queued);h->ActiveBridges=(ULONGLONG)SqActiveBridges();
        // Runtime qualification is an external acceptance gate, never asserted
        // by merely starting this private research driver.
        return Complete(irp,STATUS_SUCCESS,sizeof(*h));
    }
    return Complete(irp,STATUS_INVALID_DEVICE_REQUEST,0);
}
NTSTATUS SqInstallDevice(PDRIVER_OBJECT driver)
{
    PDEVICE_OBJECT device=NULL;UNICODE_STRING name,link,sddl;NTSTATUS status;ULONG i;
    RtlInitUnicodeString(&name,L"\\Device\\SqSyscallObserverLab");
    RtlInitUnicodeString(&link,L"\\DosDevices\\SqSyscallObserverLab");
    RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,
        FALSE,&sddl,&DeviceClass,&device);
    if(!NT_SUCCESS(status))return status;
    for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=Dispatch;
    device->Flags|=DO_BUFFERED_IO;
    status=IoCreateSymbolicLink(&link,&name);
    if(!NT_SUCCESS(status)){IoDeleteDevice(device);return status;}
    // No live unload until lifetime and device cleanup are independently
    // qualified. Initial private cleanup is normal guest reboot, never force.
    driver->DriverUnload=NULL;
    device->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;
}
