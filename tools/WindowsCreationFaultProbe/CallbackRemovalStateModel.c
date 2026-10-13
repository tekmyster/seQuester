/* Actual DiagUnregisterCore body is frozen by the build script into the include.
 * Only OS primitives are stubbed. No claim of native callback synchronization. */
typedef void VOID;typedef long NTSTATUS;typedef long LONG;typedef unsigned char BOOLEAN;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022UL)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001UL)
#define NT_SUCCESS(x) ((x)>=0)
#define SQ_EXECUTABLE_STAGING_DIAGNOSTIC 1
static BOOLEAN DiagProcessRegistered,DiagImageRegistered;
static LONG DiagStopping;
static unsigned processCalls,imageCalls,disableCalls,quiesceCalls,checks,failed;
static NTSTATUS processStatus,imageStatus,quiesceStatus;
static void Check(int condition){checks++;if(!condition)failed=1;}
static LONG InterlockedExchange(LONG* value,LONG next){LONG old=*value;*value=next;return old;}
static VOID DiagDisable(VOID){disableCalls++;}
static NTSTATUS StQuiesce(VOID){quiesceCalls++;return quiesceStatus;}
static VOID DiagProcess(VOID){}
static VOID DiagImage(VOID){}
static NTSTATUS PsSetCreateProcessNotifyRoutineEx(VOID(*callback)(VOID),BOOLEAN remove){Check(callback==DiagProcess&&remove);processCalls++;return processStatus;}
static NTSTATUS PsRemoveLoadImageNotifyRoutine(VOID(*callback)(VOID)){Check(callback==DiagImage);imageCalls++;return imageStatus;}
#include "CallbackRemovalCore.inc"
__declspec(dllexport) int RunModel(unsigned* count)
{
    checks=failed=processCalls=imageCalls=disableCalls=quiesceCalls=0;DiagStopping=0;
    DiagProcessRegistered=DiagImageRegistered=TRUE;processStatus=STATUS_ACCESS_DENIED;imageStatus=quiesceStatus=STATUS_SUCCESS;
    Check(DiagUnregisterCore()==STATUS_ACCESS_DENIED);
    Check(DiagStopping==1&&DiagProcessRegistered&&DiagImageRegistered&&processCalls==1&&imageCalls==0&&disableCalls==1&&quiesceCalls==1);
    processStatus=STATUS_SUCCESS;imageStatus=STATUS_UNSUCCESSFUL;
    Check(DiagUnregisterCore()==STATUS_UNSUCCESSFUL);
    Check(!DiagProcessRegistered&&DiagImageRegistered&&processCalls==2&&imageCalls==1);
    imageStatus=STATUS_SUCCESS;
    Check(DiagUnregisterCore()==STATUS_SUCCESS);
    Check(!DiagProcessRegistered&&!DiagImageRegistered&&processCalls==2&&imageCalls==2);
    Check(DiagUnregisterCore()==STATUS_SUCCESS&&processCalls==2&&imageCalls==2);
    DiagProcessRegistered=DiagImageRegistered=TRUE;quiesceStatus=STATUS_ACCESS_DENIED;
    Check(DiagUnregisterCore()==STATUS_ACCESS_DENIED);
    Check(DiagProcessRegistered&&DiagImageRegistered&&processCalls==2&&imageCalls==2);
    quiesceStatus=STATUS_SUCCESS;DiagProcessRegistered=FALSE;
    Check(DiagUnregisterCore()==STATUS_SUCCESS&&!DiagImageRegistered&&processCalls==2&&imageCalls==3);
    *count=checks;return failed?2:0;
}
