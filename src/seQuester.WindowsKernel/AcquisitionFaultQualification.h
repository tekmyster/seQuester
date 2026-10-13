#pragma once
// Qualification only. No actor/path selector, fake callback or caller-I/O change.
#define SQ_ARM_ACQUISITION_FAULT 41u
#define SQ_GET_ACQUISITION_FAULT_HEALTH 42u
#define SQ_ACQ_FAULT_FLAG 8u
typedef struct _AF_RULE {
    UUID Nonce;
    ULONG Stage;
    NTSTATUS Status;
    BOOLEAN Armed;
    ULONGLONG Deadline;
} AF_RULE;
typedef struct _AF_REQUEST {
    ULONG Version,Command;
    UUID Provider;
    ULONGLONG Epoch;
    UUID Nonce;
    ULONG Stage;
    NTSTATUS Status;
    ULONG ConsumeOnce,ExpiryMilliseconds;
} AF_REQUEST;
typedef struct _AF_HEALTH {
    ULONG Version,Size;
    UUID Provider;
    ULONGLONG Epoch;
    UUID Nonce;
    ULONG Stage;
    NTSTATUS Status;
    ULONG Armed,Consumed;
    ULONGLONG Arms,Consumptions,Expiries,DeadlineInterruptTime;
} AF_HEALTH;
C_ASSERT(sizeof(AF_REQUEST)==64);
C_ASSERT(sizeof(AF_HEALTH)==96);
static AF_RULE AfRule;
static ULONGLONG AfArms,AfConsumptions,AfExpiries;
static BOOLEAN AfConsumed;
static VOID AfExpireLocked(VOID)
{
    if(AfRule.Armed&&AfRule.Deadline<=KeQueryInterruptTime()){AfRule.Armed=FALSE;AfExpiries++;}
}
static VOID AfClear(VOID)
{KIRQL old;KeAcquireSpinLock(&StLock,&old);AfRule.Armed=FALSE;KeReleaseSpinLock(&StLock,old);}
static BOOLEAN AfConsume(ULONG stage,NTSTATUS* status,ULONG* flags)
{
    KIRQL old;BOOLEAN consumed=FALSE;
    KeAcquireSpinLock(&StLock,&old);AfExpireLocked();
    if(StEnabled&&AfRule.Armed&&AfRule.Stage==stage){
        AfRule.Armed=FALSE;AfConsumed=TRUE;AfConsumptions++;*status=AfRule.Status;*flags=SQ_ACQ_FAULT_FLAG;consumed=TRUE;
    }
    KeReleaseSpinLock(&StLock,old);return consumed;
}
static NTSTATUS AfMessage(PVOID input,ULONG inputBytes,PVOID output,ULONG outputBytes,PULONG returned,ULONGLONG epoch)
{
    const UUID zero={0};ULONG command;KIRQL old;NTSTATUS status=STATUS_INVALID_PARAMETER;
    if(inputBytes<8)return status;command=((ULONG*)input)[1];
    if(command==SQ_ARM_ACQUISITION_FAULT){
        AF_REQUEST q;NTSTATUS expected;
        if(inputBytes!=sizeof(q)||outputBytes!=0)return status;RtlCopyMemory(&q,input,sizeof(q));
        if(q.Version!=4||q.Epoch!=epoch||!RtlEqualMemory(&q.Provider,&SbHealth.Provider,sizeof(UUID))||RtlEqualMemory(&q.Nonce,&zero,sizeof(UUID))||
            q.Stage<1||q.Stage>9||q.ConsumeOnce!=1||q.ExpiryMilliseconds<1||q.ExpiryMilliseconds>5000)return status;
        expected=q.Stage==5||q.Stage>=7?STATUS_IO_DEVICE_ERROR:STATUS_INSUFFICIENT_RESOURCES;
        if(q.Status!=expected)return status;
        KeAcquireSpinLock(&StLock,&old);AfExpireLocked();
        if(!StEnabled)status=STATUS_DELETE_PENDING;
        else if(AfRule.Armed||RtlEqualMemory(&q.Nonce,&AfRule.Nonce,sizeof(UUID)))status=STATUS_DEVICE_BUSY;
        else{AfRule.Nonce=q.Nonce;AfRule.Stage=q.Stage;AfRule.Status=q.Status;AfRule.Deadline=KeQueryInterruptTime()+(ULONGLONG)q.ExpiryMilliseconds*10000ULL;AfRule.Armed=TRUE;AfConsumed=FALSE;AfArms++;status=STATUS_SUCCESS;}
        KeReleaseSpinLock(&StLock,old);return status;
    }
    if(command==SQ_GET_ACQUISITION_FAULT_HEALTH){
        AF_HEALTH h={0};
        if(inputBytes!=8||!output||outputBytes<sizeof(h))return status;
        h.Version=1;h.Size=sizeof(h);h.Provider=SbHealth.Provider;h.Epoch=epoch;
        KeAcquireSpinLock(&StLock,&old);AfExpireLocked();h.Nonce=AfRule.Nonce;h.Stage=AfRule.Stage;h.Status=AfRule.Status;
        h.Armed=AfRule.Armed;h.Consumed=AfConsumed;h.Arms=AfArms;h.Consumptions=AfConsumptions;h.Expiries=AfExpiries;h.DeadlineInterruptTime=AfRule.Deadline;KeReleaseSpinLock(&StLock,old);
        RtlCopyMemory(output,&h,sizeof(h));*returned=sizeof(h);return STATUS_SUCCESS;
    }
    return status;
}
