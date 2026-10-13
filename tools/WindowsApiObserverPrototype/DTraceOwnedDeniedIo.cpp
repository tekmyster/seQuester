// Owned lab fixture only. No injected observer; no kernel patches.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <string>
#include <vector>
extern "C" NTSTATUS SqOwnedDirectRead(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG,DWORD);
using ReadFn=NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
using SetFn=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
struct RenameInfo { BOOLEAN Replace; HANDLE Root; ULONG Bytes; WCHAR Name[1]; };
struct Case { const char* Operation; HANDLE Handle; ULONG Length; ULONG Class; NTSTATUS Status; };
int wmain(int count,wchar_t** args){
 if(count!=5)return 2;
 auto module=GetModuleHandleW(L"ntdll.dll");auto read=(ReadFn)GetProcAddress(module,"NtReadFile");
 auto write=(ReadFn)GetProcAddress(module,"NtWriteFile");auto set=(SetFn)GetProcAddress(module,"NtSetInformationFile");
 auto code=(const BYTE*)read;if(!code||!write||!set||code[0]!=0x4c||code[1]!=0x8b||code[2]!=0xd1||code[3]!=0xb8)return 3;
 DWORD service=0;memcpy(&service,code+4,sizeof(service));
 HANDLE readable=CreateFileW(args[1],GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 HANDLE writable=CreateFileW(args[1],GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(readable==INVALID_HANDLE_VALUE||writable==INVALID_HANDLE_VALUE)return 4;
 HANDLE ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,args[2]),release=OpenEventW(SYNCHRONIZE,FALSE,args[3]);if(!ready||!release)return 5;
 // All handles are opened successfully before trace attachment. Failed opens
 // therefore cannot substitute for these later failed operations.
 SetEvent(ready);if(WaitForSingleObject(release,60000)!=WAIT_OBJECT_0)return 6;
 FILETIME created,exit,kernel,user;if(!GetProcessTimes(GetCurrentProcess(),&created,&exit,&kernel,&user))return 7;
 char byte=0;IO_STATUS_BLOCK io{};LARGE_INTEGER offset{},append;append.QuadPart=-1;
 std::wstring destination=L"\\??\\"+std::wstring(args[1])+L".renamed";
 ULONG nameBytes=(ULONG)(destination.size()*sizeof(WCHAR));
 ULONG renameBytes=(ULONG)FIELD_OFFSET(RenameInfo,Name)+nameBytes;
 std::vector<BYTE> storage(renameBytes);auto rename=(RenameInfo*)storage.data();
 rename->Bytes=nameBytes;memcpy(rename->Name,destination.data(),nameBytes);
 LARGE_INTEGER size{};BOOLEAN deletion=TRUE;
 Case cases[]={
  {"read",writable,1,0,read(writable,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr)},
  {"write",readable,1,0,write(readable,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr)},
  {"append",readable,1,0,write(readable,nullptr,nullptr,nullptr,&io,&byte,1,&append,nullptr)},
  {"truncate",readable,sizeof(size),20,set(readable,&io,&size,sizeof(size),(FILE_INFORMATION_CLASS)20)},
  {"rename",readable,renameBytes,10,set(readable,&io,rename,renameBytes,(FILE_INFORMATION_CLASS)10)},
  {"delete",readable,sizeof(deletion),13,set(readable,&io,&deletion,sizeof(deletion),(FILE_INFORMATION_CLASS)13)},
  {"direct_read",writable,1,0,SqOwnedDirectRead(writable,nullptr,nullptr,nullptr,&io,&byte,1,&offset,nullptr,service)}
 };
 FILE* report=nullptr;if(_wfopen_s(&report,args[4],L"wx")||!report)return 8;
 bool passed=true;
 fprintf(report,"{\"Pid\":%lu,\"ThreadId\":%lu,\"ProcessBirth\":%llu,\"ObserverInjected\":false,\"ThreadTokensCollected\":false,\"Cases\":[",GetCurrentProcessId(),GetCurrentThreadId(),((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime);
 for(size_t i=0;i<_countof(cases);i++){
  const auto& c=cases[i];if(c.Status!=(NTSTATUS)0xc0000022)passed=false;
  fprintf(report,"%s{\"Operation\":\"%s\",\"Handle\":%llu,\"Length\":%lu,\"InformationClass\":%lu,\"Status\":\"0x%08lX\"}",i?",":"",c.Operation,(ULONGLONG)(ULONG_PTR)c.Handle,c.Length,c.Class,(DWORD)c.Status);
 }
 fprintf(report,"]}\n");bool saved=fflush(report)==0;int close=fclose(report);
 CloseHandle(readable);CloseHandle(writable);CloseHandle(ready);CloseHandle(release);
 return passed&&saved&&close==0?0:9;
}
