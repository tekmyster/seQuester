// Private guest-mode backend glue. Not VM-exit code, not production-qualified.
// Replaces the DdiMon demonstration handlers in a frozen research build.
#include "Capture.h"
#include "Bridge.h"
#include "CodePin.h"
// WDK FLT_PARAMETERS deliberately has alignment padding. Keep /WX on our code.
#pragma warning(push)
#pragma warning(disable:4324)
#include "ddi_mon.h"
#include "shadow_hook.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#pragma warning(pop)

using ReadWrite = NTSTATUS (NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,
    PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
using SetInformation = NTSTATUS (NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,
    FILE_INFORMATION_CLASS);

static ShadowHookTarget Targets[]={
    {RTL_CONSTANT_STRING(L"NtReadFile"),reinterpret_cast<void*>(SqReadEntry),nullptr},
    {RTL_CONSTANT_STRING(L"NtWriteFile"),reinterpret_cast<void*>(SqWriteEntry),nullptr},
    {RTL_CONSTANT_STRING(L"NtSetInformationFile"),reinterpret_cast<void*>(SqSetEntry),nullptr}
};
static PMDL CodePages[3];

// Do not probe user pointers or change output buffers. Scalar entry arguments
// and the actual returned status suffice for the first denied-handle proof.
extern "C" NTSTATUS NTAPI SqReadBody(HANDLE h,HANDLE e,PIO_APC_ROUTINE a,PVOID c,
    PIO_STATUS_BLOCK io,PVOID b,ULONG n,PLARGE_INTEGER off,PULONG key)
{
    SQ_SYSCALL_CALL call;
    SqSyscallEnter(h,SQ_SYSCALL_READ,n,0,&call);
    NTSTATUS result=reinterpret_cast<ReadWrite>(Targets[0].original_call)(h,e,a,c,io,b,n,off,key);
    SqSyscallReturn(&call,result);return result;
}
extern "C" NTSTATUS NTAPI SqWriteBody(HANDLE h,HANDLE e,PIO_APC_ROUTINE a,PVOID c,
    PIO_STATUS_BLOCK io,PVOID b,ULONG n,PLARGE_INTEGER off,PULONG key)
{
    SQ_SYSCALL_CALL call;
    SqSyscallEnter(h,SQ_SYSCALL_WRITE,n,0,&call);
    NTSTATUS result=reinterpret_cast<ReadWrite>(Targets[1].original_call)(h,e,a,c,io,b,n,off,key);
    SqSyscallReturn(&call,result);return result;
}
extern "C" NTSTATUS NTAPI SqSetBody(HANDLE h,PIO_STATUS_BLOCK io,PVOID b,ULONG n,
    FILE_INFORMATION_CLASS kind)
{
    SQ_SYSCALL_CALL call;
    SqSyscallEnter(h,SQ_SYSCALL_SET_INFORMATION,n,static_cast<ULONG>(kind),&call);
    NTSTATUS result=reinterpret_cast<SetInformation>(Targets[2].original_call)(h,io,b,n,kind);
    SqSyscallReturn(&call,result);return result;
}

extern "C" NTSTATUS DdimonInitialization(SharedShadowHookData* data)
{
    // Native capture is initialized by the driver before virtualization.
    // Installation admission rejects unsupported first instructions in the
    // frozen shadow_hook implementation. No Zw wrappers or hiding handlers.
    ULONG index=0;
    for(auto& target:Targets){
        PVOID address=MmGetSystemRoutineAddress(&target.target_name);
        if(!address)return STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS status=SqPinCodePage(address,&CodePages[index++]);
        if(!NT_SUCCESS(status))return status;
        if(!ShInstallHook(data,address,&target))return STATUS_NOT_SUPPORTED;
    }
    return ShEnableHooks();
}
extern "C" void DdimonTermination()
{
    while(!NT_SUCCESS(ShDisableHooks()))UtilSleep(10);
    // Must run before VmpStopVm. Disable redirects on every CPU, then retain
    // virtualization until root-accounted bridges have returned to callers.
    // No arbitrary fixed sleep and no guest epilogue after the decrement.
    while(SqActiveBridges()!=0)UtilSleep(10);
    for(auto& page:CodePages){SqReleaseCodePage(page);page=nullptr;}
    // Trampolines remain until guest reboot in the first private candidate.
    // Dynamic unload remains prohibited pending lifecycle qualification.
}
