#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include "DTraceAdapter.h"
int main(int argc,char** argv)
{
    if(argc!=2)return 2;
    DWORD code=strcmp(argv[1],"attach")==0?SQ_DTRACE_ATTACH:
        strcmp(argv[1],"restore")==0?SQ_DTRACE_RESTORE:
        strcmp(argv[1],"health")==0?SQ_DTRACE_HEALTH:0;
    if(!code)return 2;
    HANDLE device=CreateFileW(LR"(\\.\SqSyscallObserverLab)",GENERIC_READ|GENERIC_WRITE,0,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE){fprintf(stderr,"Protected device open failed: %lu\n",GetLastError());return 1;}
    DWORD bytes=0;SQ_DTRACE_HEALTH_RECORD health{};
    bool success=DeviceIoControl(device,code,nullptr,0,
        code==SQ_DTRACE_HEALTH?&health:nullptr,code==SQ_DTRACE_HEALTH?sizeof(health):0,&bytes,nullptr)!=0;
    DWORD operationError=success?0:GetLastError();
    if(code!=SQ_DTRACE_HEALTH){
        if(!DeviceIoControl(device,SQ_DTRACE_HEALTH,nullptr,0,&health,sizeof(health),&bytes,nullptr)){
            fprintf(stderr,"Health collection failed: %lu\n",GetLastError());CloseHandle(device);return 1;
        }
    }
    CloseHandle(device);
    if(bytes!=sizeof(health)||health.Version!=1||health.Size!=sizeof(health))return 1;
    printf("{\"Operation\":\"%s\",\"Succeeded\":%s,\"Win32Error\":%lu,\"Attached\":%lu,"
        "\"Observed\":%llu,\"Lost\":%llu,\"Queued\":%lu,\"BoundProbes\":%lu,"
        "\"AdmissionStatus\":\"0x%08lX\",\"UnregisterStatus\":\"0x%08lX\","
        "\"RegisterStatus\":\"0x%08lX\",\"RestoreStatus\":\"0x%08lX\",\"RuntimeQualified\":false}\n",
        argv[1],success?"true":"false",operationError,health.Attached,health.Observed,health.Lost,
        health.Queued,health.BoundProbes,static_cast<unsigned long>(health.AdmissionStatus),
        static_cast<unsigned long>(health.UnregisterStatus),static_cast<unsigned long>(health.RegisterStatus),
        static_cast<unsigned long>(health.RestoreStatus));
    printf("{\"PrivateDiagnostics\":true,\"RegisterCalls\":%llu,\"LookupCalls\":%llu,\"CreateCalls\":%llu,\"FireCalls\":%llu,\"ArmedFireCalls\":%llu,\"CandidateSyscallProvider\":%llu,\"BoundSyscallProvider\":%llu,\"CallbackBytes\":%lu,\"LastArmedProbeId\":%lu,\"LastArmedIrql\":%lu,\"MatchedLookupCalls\":%lu}\n",
        health.RegisterCalls,health.LookupCalls,health.CreateCalls,health.FireCalls,health.ArmedFireCalls,
        health.CandidateSyscallProvider,health.BoundSyscallProvider,health.CallbackBytes,health.LastArmedProbeId,health.LastArmedIrql,health.MatchedLookupCalls);
    return success?0:1;
}
