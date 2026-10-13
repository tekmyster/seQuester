#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include "Wire.h"
#include "Device.h"

static bool Save(const std::wstring& path,const void* data,DWORD length)
{
    HANDLE f=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE)return false;
    DWORD written=0;bool ok=WriteFile(f,data,length,&written,nullptr)!=0&&written==length&&FlushFileBuffers(f)!=0;CloseHandle(f);return ok;
}
int wmain(int argc,wchar_t** argv)
{
    wchar_t machine[64]{};DWORD size=64;
    if(argc!=2||!GetComputerNameW(machine,&size)||wcscmp(machine,L"SQ-KERNEL-W10")!=0)return 2;
    std::wstring root=argv[1];
    if(root.rfind(L"C:\\Windows\\Temp\\sq-syscall-",0)!=0||root.find(L"..")!=std::wstring::npos||root.back()==L'\\'||!CreateDirectoryW(root.c_str(),nullptr))return 2;
    HANDLE device=CreateFileW(LR"(\\.\SqSyscallObserverLab)",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE){std::printf("{\"DeviceOpen\":false,\"Win32Error\":%lu}\n",GetLastError());return 1;}
    DWORD received=0;SQ_SOURCE_INFO source{};SQ_SYSCALL_RECORD record{};
    bool gotSource=DeviceIoControl(device,SQ_SOURCE,nullptr,0,&source,sizeof(source),&received,nullptr)!=0&&received==sizeof(source)&&source.Version==1&&source.Size==sizeof(source);
    DWORD sourceError=gotSource?0:GetLastError();
    bool gotRecord=DeviceIoControl(device,SQ_PEEK,nullptr,0,&record,sizeof(record),&received,nullptr)!=0&&received==sizeof(record)&&record.Version==1&&record.Size==sizeof(record);
    DWORD recordError=gotRecord?0:GetLastError();CloseHandle(device);
    bool saved=(!gotSource||Save(root+L"\\source.bin",&source,sizeof(source)))&&(!gotRecord||Save(root+L"\\head.bin",&record,sizeof(record)));
    char output[512]{};int length=sprintf_s(output,"{\"ReadOnly\":true,\"SourceCaptured\":%s,\"SourceError\":%lu,\"Queued\":%lu,\"Observed\":%llu,\"Lost\":%llu,\"HeadCaptured\":%s,\"HeadError\":%lu,\"HeadSequence\":%llu,\"Saved\":%s}",gotSource?"true":"false",sourceError,source.Queued,source.Observed,source.Lost,gotRecord?"true":"false",recordError,gotRecord?record.Sequence:0,saved?"true":"false");
    if(length<=0||!Save(root+L"\\result.json",output,static_cast<DWORD>(length)))return 1;
    std::printf("%s\n",output);return gotSource&&saved?0:1;
}
