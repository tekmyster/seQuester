#include "Bridge.h"
static volatile LONG64 ActiveBridges;
void SqRootEnter(void){InterlockedIncrement64(&ActiveBridges);}
LONG64 SqActiveBridges(void){return InterlockedCompareExchange64(&ActiveBridges,0,0);}
BOOLEAN SqRootReturn(ULONG_PTR ip,ULONG_PTR returnIp,ULONG_PTR returnSp)
{
    if(ip!=(ULONG_PTR)SqReadReturnVmcall&&ip!=(ULONG_PTR)SqWriteReturnVmcall&&
        ip!=(ULONG_PTR)SqSetReturnVmcall)return FALSE;
    if(returnIp<(ULONG_PTR)MmSystemRangeStart||returnSp<(ULONG_PTR)MmSystemRangeStart||
        (returnSp&7)!=0||SqActiveBridges()<=0)return FALSE;
    // VM-exit will redirect straight to the original caller. No callback
    // epilogue remains in the guest after the count reaches zero.
    InterlockedDecrement64(&ActiveBridges);return TRUE;
}
