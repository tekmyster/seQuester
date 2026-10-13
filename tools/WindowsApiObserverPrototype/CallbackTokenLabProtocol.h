#pragma once
#define SQ_CB_ARM CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_READ_ACCESS)
#define SQ_CB_PEEK CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct _SQ_CB_ARM_INPUT { ULONG Mode,Reserved; ULONGLONG FileHandle; } SQ_CB_ARM_INPUT;
#define SQ_CB_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct _SQ_CB_REPLY {
    ULONG Version,Size,CallbackIrql,ReferenceIrql,QueryIrql,ForcedApc;
    ULONG Impersonating,CopyOnOpen,EffectiveOnly,Level;
    LONG UserStatus,StatisticsStatus,OperationStatus;
    ULONG Completed;
    ULONGLONG Pid,Tid,ProcessBirth,Callbacks;
    LUID TokenId,AuthenticationId,ModifiedId;
    ULONGLONG TargetCallbacks,NullThreadCallbacks,OtherThreadCallbacks,LastCallbackTid;
    ULONG LastCallbackIrql;
    ULONGLONG ArmedReadCallbacks,OwnerReadCallbacks,TargetNameCallbacks;
    ULONG LastOwnerSameDevice,LastOwnerSameName,LastOwnerNameBytes,ArmedNameBytes;
    ULONG SidBytes;
    UCHAR Sid[68];
} SQ_CB_REPLY;

#define SQ_CB_SENDER_READ CTL_CODE(FILE_DEVICE_UNKNOWN,0x815,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct _SQ_CB_SENDER_REPLY { ULONG Version,Size,SubmitIrql,FirstByte; LONG OperationStatus; ULONG Reserved; ULONGLONG BytesRead; } SQ_CB_SENDER_REPLY;
