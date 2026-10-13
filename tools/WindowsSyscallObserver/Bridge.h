#pragma once
#include <ntifs.h>
#define SQ_RETURN_HYPERCALL 0x53510001UL
#ifdef __cplusplus
extern "C" {
#endif
void SqReadEntry(void);
void SqWriteEntry(void);
void SqSetEntry(void);
void SqReadReturnVmcall(void);
void SqWriteReturnVmcall(void);
void SqSetReturnVmcall(void);
// Root-context primitives: atomic operations and address comparisons only.
void SqRootEnter(void);
BOOLEAN SqRootReturn(ULONG_PTR instruction, ULONG_PTR returnIp, ULONG_PTR returnSp);
LONG64 SqActiveBridges(void);
#ifdef __cplusplus
}
#endif
