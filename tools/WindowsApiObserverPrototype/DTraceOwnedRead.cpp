#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
extern "C" NTSTATUS SqOwnedDirectRead(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG,DWORD);
using ReadFn=NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
// Barrier lets the controller attach a PID-scoped kernel trace before issuing
// any operation. No injected observer, global hooks or executable modification.
int wmain(int count,wchar_t** args){
 if(count!=5)return 2;
 auto function=(ReadFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtReadFile");auto code=(const BYTE*)function;
 if(!code||code[0]!=0x4c||code[1]!=0x8b||code[2]!=0xd1||code[3]!=0xb8)return 3;
 DWORD service=0;memcpy(&service,code+4,sizeof(service));
 HANDLE file=CreateFileW(args[1],GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)return 4;
 HANDLE ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,args[2]);HANDLE release=OpenEventW(SYNCHRONIZE,FALSE,args[3]);if(!ready||!release)return 5;
 SetEvent(ready);if(WaitForSingleObject(release,30000)!=WAIT_OBJECT_0)return 6;
 BYTE byte=0;IO_STATUS_BLOCK io={};LARGE_INTEGER offset={};FILETIME created,exit,kernel,user;
 if(!GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user))return 7;
 NTSTATUS normal=function(file,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr);
 NTSTATUS direct=SqOwnedDirectRead(file,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr,service);
 char output[1024];int length=sprintf_s(output,"{\"Pid\":%lu,\"ThreadId\":%lu,\"ProcessBirth\":%llu,\"FileHandle\":%llu,\"Length\":1,\"NormalStatus\":\"0x%08lX\",\"DirectStatus\":\"0x%08lX\",\"ObserverInjected\":false}\n",GetCurrentProcessId(),GetCurrentThreadId(),((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime,(ULONGLONG)(ULONG_PTR)file,(DWORD)normal,(DWORD)direct);
 HANDLE report=CreateFileW(args[4],GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);DWORD written=0;if(report==INVALID_HANDLE_VALUE)return 8;
 BOOL saved=WriteFile(report,output,(DWORD)length,&written,nullptr);FlushFileBuffers(report);CloseHandle(report);CloseHandle(file);CloseHandle(ready);CloseHandle(release);
 return saved&&written==(DWORD)length&&normal==(NTSTATUS)0xc0000022&&direct==(NTSTATUS)0xc0000022?0:9;
}
