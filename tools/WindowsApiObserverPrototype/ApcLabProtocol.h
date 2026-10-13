#pragma once
#define SQ_PIN CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_READ_ACCESS)
#define SQ_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_ACCESS)
#define SQ_RELEASE CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct _SQ_LAB_REPLY {
    ULONG Version, Size, ReferenceIrql, QueryIrql;
    ULONG Impersonating, CopyOnOpen, EffectiveOnly, Level;
    LONG UserStatus, StatisticsStatus;
    ULONGLONG Pid, Tid;
    LUID TokenId, AuthenticationId, ModifiedId;
    ULONG SidBytes;
    UCHAR Sid[68];
} SQ_LAB_REPLY;
