#pragma once
#include <ntifs.h>
#include "Protocol.h"

#include "Wire.h"
typedef struct _SQ_SYSCALL_CALL {
    BOOLEAN Observed;
    SQ_SYSCALL_RECORD Record;
    PFILE_OBJECT Target;
} SQ_SYSCALL_CALL;

#ifdef __cplusplus
extern "C" {
#endif
VOID SqSyscallInitialize(VOID);
BOOLEAN SqSyscallIsArmedCurrentThread(VOID);
// Restricted first qualification: invoking admin device thread arms its own
// handles only. Device authorization is enforced by the driver, not this helper.
NTSTATUS SqSyscallArmCurrentThread(const HANDLE* handles, ULONG count);
NTSTATUS SqSyscallDisarmCurrentThread(VOID);
BOOLEAN SqSyscallEnter(HANDLE handle, ULONG operation, ULONG length,
    ULONG informationClass, SQ_SYSCALL_CALL* call);
VOID SqSyscallReturn(SQ_SYSCALL_CALL* call, NTSTATUS result);
NTSTATUS SqSyscallReadRecord(SQ_SYSCALL_RECORD* record);
VOID SqSyscallHealth(ULONGLONG* observed, ULONGLONG* lost, ULONG* queued);
NTSTATUS SqSyscallIntake(ULONG code,PVOID buffer,ULONG inputBytes,ULONG outputBytes,PULONG returned);
#ifdef __cplusplus
}
#endif
