#pragma once
#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif
#include "Protocol.h"
// Private research contract. No production source advertises this schema.
// Caller must execute in the original guest thread, NEVER VM-exit/root context.
#define SQ_SYSCALL_SCHEMA 1
#define SQ_SYSCALL_CAPACITY 128
#define SQ_SYSCALL_TARGETS 8
#define SQ_SYSCALL_READ 1
#define SQ_SYSCALL_WRITE 2
#define SQ_SYSCALL_SET_INFORMATION 3

typedef struct _SQ_SYSCALL_RECORD {
    ULONG Version, Size;
    ULONGLONG Sequence, EntryUtc, EntryMonotonic, ReturnUtc, ReturnMonotonic;
    ULONGLONG ProcessId, ThreadId, ProcessBirth, TargetHandle;
    ULONG Operation, InformationClass, RequestedLength;
    LONG ReturnStatus, AttributionStatus, FileObjectStatus;
    ULONG ImpersonationState, CaptureIrql, RequestorMode, Reserved;
    // Submission status only; async completion/bytes are unavailable in v1.
    SQ_TOKEN Owner, Effective;
} SQ_SYSCALL_RECORD;
