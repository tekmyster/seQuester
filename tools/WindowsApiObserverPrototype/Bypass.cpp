#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
extern "C" NTSTATUS SqOwnedDirectRead(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG,DWORD);
using ReadFn=NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
int wmain(int count,wchar_t** args){
    if(count!=4)return 2;bool direct=!wcscmp(args[1],L"direct");if(!direct&&wcscmp(args[1],L"normal"))return 3;
    auto observer=GetModuleHandleW(L"Observer64.dll");auto serviceFn=(DWORD(__cdecl*)())GetProcAddress(observer,"ObserverNtReadService");
    if(!serviceFn)return 4;DWORD service=serviceFn();if(service==0xffffffff)return 5;
    HANDLE file=CreateFileW(args[2],GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return 6;
    BYTE byte=0;IO_STATUS_BLOCK io={};LARGE_INTEGER offset={};
    NTSTATUS status=direct?SqOwnedDirectRead(file,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr,service):((ReadFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtReadFile"))(file,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr);
    CloseHandle(file);char output[512];int length=sprintf_s(output,"{\"PrototypeNegativeFixture\":true,\"Pid\":%lu,\"ThreadId\":%lu,\"Direct\":%s,\"NtStatus\":\"0x%08lX\"}\n",GetCurrentProcessId(),GetCurrentThreadId(),direct?"true":"false",(DWORD)status);
    HANDLE report=CreateFileW(args[3],GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);DWORD written=0;
    if(report==INVALID_HANDLE_VALUE)return 8;BOOL saved=WriteFile(report,output,(DWORD)length,&written,nullptr);FlushFileBuffers(report);CloseHandle(report);if(!saved||written!=(DWORD)length)return 9;
    return status==(NTSTATUS)0xC0000022?0:7;
}
