#pragma once
#include <ntifs.h>
#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS SqPinCodePage(PVOID address,PMDL* output);
VOID SqReleaseCodePage(PMDL mdl);
#ifdef __cplusplus
}
#endif
