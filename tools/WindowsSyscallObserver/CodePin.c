#include "CodePin.h"
NTSTATUS SqPinCodePage(PVOID address,PMDL* output)
{
    PMDL mdl;NTSTATUS status=STATUS_SUCCESS;
    *output=NULL;
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
    mdl=IoAllocateMdl(PAGE_ALIGN(address),PAGE_SIZE,FALSE,FALSE,NULL);
    if(!mdl)return STATUS_INSUFFICIENT_RESOURCES;
    // Nt* exports may be pageable. Keep the actual physical source page alive
    // while EPT refers to it; mere export resolution does not pin a code page.
    __try{MmProbeAndLockPages(mdl,KernelMode,IoReadAccess);}
    __except(EXCEPTION_EXECUTE_HANDLER){status=GetExceptionCode();}
    if(!NT_SUCCESS(status)){IoFreeMdl(mdl);return status;}
    *output=mdl;return STATUS_SUCCESS;
}
VOID SqReleaseCodePage(PMDL mdl)
{
    if(!mdl)return;
    MmUnlockPages(mdl);IoFreeMdl(mdl);
}
