/* Executes the actual diagnostic scalar functions with OS primitives stubbed.
 * This is not a Windows scheduler/rundown or native race-reproduction test. */
#include <stdint.h>
#ifndef SQ_CF_MODEL_DLL
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#else
static unsigned modelFailed;
#define assert(x) ((void)((x)?0:(modelFailed=1)))
static void* ModelCopy(void* destination,const void* source,unsigned long long length){unsigned char* d=destination;const unsigned char* s=source;unsigned long long i;for(i=0;i<length;i++)d[i]=s[i];return destination;}
static void* ModelSet(void* destination,int value,unsigned long long length){unsigned char* d=destination;unsigned long long i;for(i=0;i<length;i++)d[i]=(unsigned char)value;return destination;}
static int ModelCompare(const void* first,const void* second,unsigned long long length){const unsigned char* a=first;const unsigned char* b=second;unsigned long long i;for(i=0;i<length;i++)if(a[i]!=b[i])return 1;return 0;}
#define memcpy ModelCopy
#define memset ModelSet
#define memcmp ModelCompare
#endif
typedef void VOID;typedef void* PVOID;typedef void* HANDLE;typedef void* PEPROCESS;
typedef unsigned long ULONG;typedef ULONG* PULONG;typedef unsigned long long ULONGLONG;
typedef long NTSTATUS;typedef unsigned char BOOLEAN;typedef int KIRQL;typedef int KSPIN_LOCK;typedef int KMUTEX;
typedef struct {ULONG a;unsigned short b,c;unsigned char d[8];} UUID;
typedef struct {long long QuadPart;} LARGE_INTEGER;
typedef struct {struct {HANDLE UniqueProcess,UniqueThread;} CreatingThreadId;} INFO,*PPS_CREATE_NOTIFY_INFO;
#define C_ASSERT(x) _Static_assert(x,#x)
#define TRUE 1
#define FALSE 0
#define MAXULONGLONG (~0ULL)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022UL)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AUL)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DUL)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023UL)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225UL)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011UL)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AUL)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184UL)
#define PASSIVE_LEVEL 0
#define NT_SUCCESS(x) ((x)>=0)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlEqualMemory(a,b,n) (memcmp((a),(b),(n))==0)
static struct {UUID Provider;} SbHealth;
static unsigned checks;static ULONGLONG ticks=100;static int held,references,stopDuringLookup,removals,lookupCalls;
static ULONGLONG currentCreated=456;static KIRQL currentIrql;static BOOLEAN allApcsDisabled;static NTSTATUS removalStatus;
static KIRQL KeGetCurrentIrql(void){return currentIrql;}
static BOOLEAN KeAreAllApcsDisabled(void){return allApcsDisabled;}
static VOID CfStop(VOID);
static void Check(int value,const char* label){checks++;
#ifndef SQ_CF_MODEL_DLL
    if(!value){fprintf(stderr,"FAIL: %s\n",label);exit(2);}
#else
    (void)label;if(!value)modelFailed=1;
#endif
}
static void KeInitializeSpinLock(KSPIN_LOCK* lock){*lock=0;}
static void KeInitializeMutex(KMUTEX* mutex,ULONG level){(void)level;*mutex=0;}
static void KeAcquireSpinLock(KSPIN_LOCK* lock,KIRQL* old){(void)lock;assert(!held);held=1;*old=0;}
static void KeReleaseSpinLock(KSPIN_LOCK* lock,KIRQL old){(void)lock;(void)old;assert(held);held=0;}
static LARGE_INTEGER KeQueryPerformanceCounter(PVOID ignored){LARGE_INTEGER value;(void)ignored;value.QuadPart=(long long)++ticks;return value;}
static HANDLE PsGetCurrentProcessId(void){return (HANDLE)(uintptr_t)42;}
static HANDLE PsGetCurrentThreadId(void){return (HANDLE)(uintptr_t)77;}
static NTSTATUS PsLookupProcessByProcessId(HANDLE pid,PEPROCESS* process){assert(!held);lookupCalls++;if(stopDuringLookup){stopDuringLookup=0;CfStop();}if(pid!=PsGetCurrentProcessId())return STATUS_NOT_FOUND;*process=(PEPROCESS)(uintptr_t)123;references++;return STATUS_SUCCESS;}
static ULONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS process){(void)process;return currentCreated;}
static VOID ObDereferenceObject(PEPROCESS process){(void)process;references--;assert(references>=0);}
#include "../../src/seQuester.WindowsKernel/CreationFaultDiagnostic.h"
static NTSTATUS DiagUnregister(VOID){assert(!held);removals++;CfStop();return removalStatus;}
static void Reset(void)
{
    memset(&CfState,0,sizeof(CfState));memset(CfRows,0,sizeof(CfRows));CfNext=CfEnd=CfInconsistent=0;CfCallbacksRemoved=0;
    held=references=stopDuringLookup=removals=lookupCalls=0;currentCreated=456;currentIrql=0;allApcsDisabled=FALSE;removalStatus=STATUS_SUCCESS;CfInitialize();
}
static CF_REQUEST Request(ULONG command)
{
    CF_REQUEST r={0};r.Version=4;r.Command=command;r.Provider=CfState.Provider;r.CreatorPid=42;r.CreatorCreated=456;r.Scenario=CfState.Scenario;return r;
}
static void Arm(void)
{
    CF_REQUEST request=Request(29);CF_STATE state;ULONG returned=0;request.Mode=CF_MISMATCH;request.Count=1;request.Scenario=0;
    Check(CfMessage(&request,sizeof(request),&state,sizeof(state),&returned,TRUE)==STATUS_SUCCESS&&returned==80,"one owned selection armed through actual command validation");
}
#ifdef SQ_CF_MODEL_DLL
__declspec(dllexport) int RunModel(unsigned* count)
#else
int main(void)
#endif
{
    unsigned scenario;
    checks=0;
#ifdef SQ_CF_MODEL_DLL
    modelFailed=0;
#endif
    for(scenario=0;scenario<6;scenario++)
    {
        INFO info={{(HANDLE)(uintptr_t)42,(HANDLE)(uintptr_t)77}};CF_SELECTION selection;CF_ROW original,stop;CF_HEALTH health;CF_REQUEST request;ULONG returned=0;
        Reset();Arm();if(scenario==0)stopDuringLookup=1;
        selection=CfSelect(&info,900,(HANDLE)(uintptr_t)101,789);
        if(scenario==0)Check(selection.Mode==0&&CfState.Pending==0,"STOP between selector snapshot/recheck prevents reservation");
        else
        {
            original=CfRows[selection.Index];Check(selection.Mode==1&&CfState.Pending==1&&original.Terminal==0,"selected invocation owns exactly one pending row");
            if(scenario!=4)CfStop();
            CfFinish(selection,1,scenario==2||scenario==5?88:0,(BOOLEAN)(scenario==2||scenario==3||scenario==5));
            Check(CfState.Pending==0,"exact finish returns pending count to zero");
            Check(CfRows[selection.Index].Terminal==(scenario==1?4u:scenario==2?5u:scenario==3?6u:scenario==4?3u:5u),"terminal agrees with actual modeled bind/STOP ordering");
            Check(CfRows[selection.Index].Candidate==original.Candidate&&CfRows[selection.Index].Pid==original.Pid&&CfRows[selection.Index].Created==original.Created&&CfRows[selection.Index].Started==original.Started&&CfRows[selection.Index].Scenario==original.Scenario&&CfRows[selection.Index].ArmGeneration==original.ArmGeneration,"reserved scalar identity remains unchanged at finish");
            Check(CfRows[selection.Index].Started<CfRows[selection.Index].Finished,"actual diagnostic QPC reservation precedes finish");
            if(scenario!=4)Check(CfRows[selection.Index].Started<CfRows[0].Started&&CfRows[0].Started<CfRows[selection.Index].Finished,"modeled overlap has strict reserve-STOP-finish order");
            if(scenario==5)
            {
                original=CfRows[selection.Index];stop=CfRows[0];CfStop();CfFinish(selection,2,0,FALSE);
                Check(!memcmp(&original,&CfRows[selection.Index],sizeof(original))&&!memcmp(&stop,&CfRows[0],sizeof(stop))&&CfState.Pending==0&&CfInconsistent,"duplicate finish records inconsistency without row mutation/underflow or duplicate STOP");
            }
        }
        CfStop();selection=CfSelect(&info,901,(HANDLE)(uintptr_t)102,790);Check(selection.Mode==0,"no selection after STOP");
        request=Request(33);Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_SUCCESS&&returned==64&&removals==1,"health invokes modeled callback-root removal outside spin lock");
        Check(health.Pending==0&&health.Selected==(scenario?1u:0u)&&health.Finalized==health.Selected&&health.StopRows==1&&health.Inconsistent==(scenario==5?1u:0u)&&health.CallbacksRemoved>=health.LastFinish,"post-removal scalar accounting is consistent with modeled outcomes");
        Check(references==0&&!held,"lookup references and mock spin lock balanced");
        request.CreatorCreated++;Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_NOT_FOUND&&removals==1,"wrong owner start time cannot invoke quiesce");
        currentCreated=request.CreatorCreated;Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_NOT_FOUND&&removals==1,"valid current requester with reused PID cannot match the previous armed creator generation");
    }
    {
        CF_REQUEST request;CF_HEALTH health;ULONG returned=0;Reset();Arm();CfStop();request=Request(33);
        lookupCalls=0;currentIrql=2;Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_INVALID_DEVICE_STATE&&removals==0&&lookupCalls==0,"non-passive command33 cannot look up owner or wait");
        currentIrql=0;allApcsDisabled=TRUE;Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_INVALID_DEVICE_STATE&&removals==0&&lookupCalls==0,"all APCs disabled cannot look up owner or remove callbacks");
        allApcsDisabled=FALSE;removalStatus=STATUS_ACCESS_DENIED;memset(&health,0x5a,sizeof(health));
        Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_ACCESS_DENIED&&returned==0&&health.Version==0x5a5a5a5aUL&&CfCallbacksRemoved==0,"removal failure publishes neither health nor callback-removed timestamp");
        removalStatus=STATUS_SUCCESS;Check(CfMessage(&request,sizeof(request),&health,sizeof(health),&returned,TRUE)==STATUS_SUCCESS&&removals==2&&health.CallbacksRemoved>0,"successful removal retry publishes health only after success");
    }
#ifdef SQ_CF_MODEL_DLL
    *count=checks;return modelFailed?2:0;
#else
    printf("{\"Passed\":true,\"Checks\":%u,\"Cases\":6,\"Scope\":\"Actual CF scalar functions with stubbed OS primitives; no real Windows callback STOP overlap claim\"}\n",checks);return 0;
#endif
}
