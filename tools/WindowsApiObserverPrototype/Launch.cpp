#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>
#include <cstdio>
#include <string>
int wmain(int count,wchar_t** args){
    if(count!=4){fwprintf(stderr,L"Usage: Launch observer.dll actor.exe command-line\n");return 2;}
    char dll[32768];if(!WideCharToMultiByte(CP_ACP,WC_NO_BEST_FIT_CHARS,args[1],-1,dll,sizeof(dll),nullptr,nullptr))return 3;
    std::wstring command=L"\""+std::wstring(args[2])+L"\" "+args[3];STARTUPINFOW startup={sizeof(startup)};PROCESS_INFORMATION p={};
    if(!DetourCreateProcessWithDllExW(args[2],&command[0],nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&p,dll,nullptr)){fwprintf(stderr,L"Creation failed: %lu\n",GetLastError());return 4;}
    FILETIME start={},end={},kernel={},user={};BOOL known=GetProcessTimes(p.hProcess,&start,&end,&kernel,&user);
    printf("{\"Pid\":%lu,\"ProcessCreatedFileTime\":%llu,\"ProcessBirthKnown\":%s}\n",p.dwProcessId,((ULONGLONG)start.dwHighDateTime<<32)|start.dwLowDateTime,known?"true":"false");fflush(stdout);
    // No forced termination. A finite observer wait preserves the owned process
    // for investigation if it does not exit normally.
    DWORD wait=WaitForSingleObject(p.hProcess,30000),exit=0;if(wait!=WAIT_OBJECT_0){CloseHandle(p.hThread);CloseHandle(p.hProcess);return 5;}
    BOOL ok=GetExitCodeProcess(p.hProcess,&exit);CloseHandle(p.hThread);CloseHandle(p.hProcess);return ok?(int)exit:6;
}
