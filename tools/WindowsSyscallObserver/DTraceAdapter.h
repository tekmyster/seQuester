#pragma once
#include "Device.h"
#define SQ_DTRACE_ATTACH CTL_CODE(FILE_DEVICE_UNKNOWN,0xB05,METHOD_BUFFERED,FILE_WRITE_DATA)
#define SQ_DTRACE_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN,0xB06,METHOD_BUFFERED,FILE_WRITE_DATA)
#define SQ_DTRACE_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN,0xB07,METHOD_BUFFERED,FILE_READ_DATA)
#define SQ_DTRACE_HEALTH CTL_CODE(FILE_DEVICE_UNKNOWN,0xB08,METHOD_BUFFERED,FILE_READ_DATA)
typedef struct _SQ_DTRACE_CONTEXT_RECORD {
    ULONG Version,Size;
    ULONGLONG Sequence,Monotonic,Utc,ProcessId,ThreadId,ProcessBirth;
    ULONG ProbeId,Operation,Stage,Irql,InterruptsEnabled,AllApcsDisabled;
    ULONGLONG Arguments[4];
} SQ_DTRACE_CONTEXT_RECORD;
typedef struct _SQ_DTRACE_HEALTH_RECORD {
    ULONG Version,Size,Attached,Queued;
    ULONGLONG Observed,Lost;
    LONG AdmissionStatus,UnregisterStatus,RegisterStatus,RestoreStatus;
    ULONG BoundProbes,Reserved;
    ULONGLONG RegisterCalls,LookupCalls,CreateCalls,FireCalls,ArmedFireCalls;
    ULONGLONG CandidateSyscallProvider,BoundSyscallProvider;
    ULONG CallbackBytes,LastArmedProbeId,LastArmedIrql,MatchedLookupCalls;
} SQ_DTRACE_HEALTH_RECORD;
#ifdef _KERNEL_MODE
NTSTATUS SqDtraceControl(ULONG code,PVOID buffer,ULONG input,ULONG output,PULONG bytes);
#endif
