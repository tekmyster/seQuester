#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include "Device.h"
#ifdef SQ_DTRACE_CONTEXT_TEST
#include "DTraceAdapter.h"
#endif
using NtReadWrite=LONG (NTAPI*)(HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,PVOID,
    ULONG,PLARGE_INTEGER,PULONG);
using NtSet=LONG (NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
static void Check(bool value,const char* what){if(!value)throw std::runtime_error(what);}
static ULONGLONG Luid(const LUID& id){ULONGLONG value;memcpy(&value,&id,sizeof(value));return value;}
static SQ_TOKEN Truth(HANDLE token)
{
    SQ_TOKEN t{};DWORD needed=0;TOKEN_STATISTICS stats{};DWORD session=0;
    TOKEN_ELEVATION elevation{};
    GetTokenInformation(token,TokenUser,nullptr,0,&needed);
    Check(needed>0,"truth user size");std::vector<unsigned char> user(needed);
    Check(GetTokenInformation(token,TokenUser,user.data(),needed,&needed)!=0,"truth user");
    PSID sid=reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    t.SidLength=GetLengthSid(sid);Check(t.SidLength<=SQ_SID_BYTES,"truth SID length");
    memcpy(t.Sid,sid,t.SidLength);
    Check(GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&needed)!=0,"truth stats");
    t.TokenId=Luid(stats.TokenId);t.ModifiedId=Luid(stats.ModifiedId);
    t.AuthenticationId=Luid(stats.AuthenticationId);t.TokenType=stats.TokenType;
    t.ImpersonationLevel=stats.TokenType==TokenImpersonation?stats.ImpersonationLevel:0xffffffffU;
    Check(GetTokenInformation(token,TokenSessionId,&session,sizeof(session),&needed)!=0,"truth session");
    t.SessionId=session;
    GetTokenInformation(token,TokenIntegrityLevel,nullptr,0,&needed);
    Check(needed>0,"truth integrity size");std::vector<unsigned char> label(needed);
    Check(GetTokenInformation(token,TokenIntegrityLevel,label.data(),needed,&needed)!=0,"truth integrity");
    sid=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(label.data())->Label.Sid;
    t.IntegrityRid=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);
    Check(GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&needed)!=0,"truth elevation");
    t.Elevated=elevation.TokenIsElevated;t.Captured=31;return t;
}
#if !defined(SQ_DTRACE_CONTEXT_TEST) && !defined(SQ_MANAGED_PRODUCER)
static bool Same(const SQ_TOKEN& a,const SQ_TOKEN& b)
{
    return a.Captured==31&&b.Captured==31&&a.TokenId==b.TokenId&&a.ModifiedId==b.ModifiedId&&
        a.AuthenticationId==b.AuthenticationId&&a.TokenType==b.TokenType&&
        a.ImpersonationLevel==b.ImpersonationLevel&&a.SessionId==b.SessionId&&
        a.IntegrityRid==b.IntegrityRid&&a.Elevated==b.Elevated&&a.SidLength==b.SidLength&&
        memcmp(a.Sid,b.Sid,a.SidLength)==0;
}
#endif
static std::string Sid(const SQ_TOKEN& t)
{
    LPSTR text=nullptr;Check(ConvertSidToStringSidA(const_cast<UCHAR*>(t.Sid),&text)!=0,"format SID");
    std::string result(text);LocalFree(text);return result;
}
static void Command(HANDLE device,DWORD code,void* input,DWORD length,void* output,DWORD size)
{
    DWORD returned=0;
    Check(DeviceIoControl(device,code,input,length,output,size,&returned,nullptr)!=0,"observer command");
    Check(returned==size,"observer response length");
}
static void NewFile(const std::wstring& path)
{
    HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);Check(h!=INVALID_HANDLE_VALUE,"new owned target");
    DWORD done=0;const char data[]="SQ01";
    bool valid=WriteFile(h,data,4,&done,nullptr)!=0&&done==4;CloseHandle(h);Check(valid,"seed target");
}
struct RenameInfo {BOOLEAN Replace;HANDLE Root;ULONG Length;WCHAR Name[1];};
#ifdef SQ_MANAGED_PRODUCER
// Independent user-mode truth only. No native record is read or acknowledged
// by this producer: the managed sensor must receive every observation itself.
struct ExpectedOperation {
    ULONG Version,Size;ULONGLONG Birth;ULONG Pid,Tid,Operation,Kind,Impersonation;
    LONG Status;ULONG RequestedLength,Reserved;SQ_TOKEN Owner,Effective;
};
static_assert(sizeof(ExpectedOperation)==336,"independent truth layout");
#endif
int wmain(int argc,wchar_t** argv)
{
#ifdef SQ_DTRACE_CONTEXT_TEST
    if(argc!=2&&argc!=4)return 2;
#else
    if(argc!=2)return 2;
#endif
    HANDLE device=INVALID_HANDLE_VALUE,file=INVALID_HANDLE_VALUE,lock=INVALID_HANDLE_VALUE,raw=INVALID_HANDLE_VALUE;
    HANDLE primary=nullptr,imp=nullptr,owner=nullptr;bool armed=false,impersonating=false;
    try{
#ifdef SQ_DTRACE_CONTEXT_TEST
        if(argc==4){
            HANDLE ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,argv[2]);
            HANDLE release=OpenEventW(SYNCHRONIZE,FALSE,argv[3]);
            Check(ready&&release,"context test barriers");Check(SetEvent(ready)!=0,"context ready");
            Check(WaitForSingleObject(release,90000)==WAIT_OBJECT_0,"context release");CloseHandle(ready);CloseHandle(release);
        }
#endif
        std::wstring root=argv[1];Check(CreateDirectoryW(root.c_str(),nullptr)!=0,"unique test directory");
        raw=CreateFileW((root+
#ifdef SQ_MANAGED_PRODUCER
            LR"(\expected-operations.bin)"
#else
            LR"(\native-records.bin)"
#endif
            ).c_str(),GENERIC_WRITE,FILE_SHARE_READ,
            nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);Check(raw!=INVALID_HANDLE_VALUE,"new raw evidence file");
        device=CreateFileW(LR"(\\.\SqSyscallObserverLab)",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        Check(device!=INVALID_HANDLE_VALUE,"protected observer open");
        SQ_OBSERVER_HEALTH health{};Command(device,SQ_HEALTH,nullptr,0,&health,sizeof(health));
        Check(health.Version==1&&health.RecordBytes==sizeof(SQ_SYSCALL_RECORD)&&health.Queued==0&&health.Lost==0,"clean observer baseline");
        Check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&owner)!=0,"owner token");
        SQ_TOKEN ownerTruth=Truth(owner);
        Check(LogonUserW(L"LocalService",L"NT AUTHORITY",L"",LOGON32_LOGON_SERVICE,LOGON32_PROVIDER_DEFAULT,&primary)!=0,"LocalService logon");
        Check(DuplicateTokenEx(primary,TOKEN_ALL_ACCESS,nullptr,SecurityImpersonation,TokenImpersonation,&imp)!=0,"LocalService impersonation token");
        FILETIME birth,exit,kernel,user;Check(GetProcessTimes(GetCurrentProcess(),&birth,&exit,&kernel,&user)!=0,"process birth");
        ULONGLONG birthId=(static_cast<ULONGLONG>(birth.dwHighDateTime)<<32)|birth.dwLowDateTime;
        HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
        auto read=reinterpret_cast<NtReadWrite>(GetProcAddress(ntdll,"NtReadFile"));
        auto write=reinterpret_cast<NtReadWrite>(GetProcAddress(ntdll,"NtWriteFile"));
        auto set=reinterpret_cast<NtSet>(GetProcAddress(ntdll,"NtSetInformationFile"));
        Check(read&&write&&set,"actual native exports");
        const char* names[]={"denied-handle-read","denied-handle-write","denied-handle-append",
            "denied-handle-truncate","denied-handle-rename","denied-handle-delete",
            "locked-handle-read","locked-handle-write","read-control"};
        unsigned passed=0;
#ifndef SQ_MANAGED_PRODUCER
        ULONGLONG priorSequence=0;
#endif
        for(unsigned n=0;n<9;n++){
            std::wstring path=root+L"\\case-"+std::to_wstring(n)+L".txt";NewFile(path);
            DWORD access=n==0?FILE_WRITE_DATA|FILE_READ_ATTRIBUTES:n<6?FILE_READ_DATA|FILE_READ_ATTRIBUTES:
                n<8?GENERIC_READ|GENERIC_WRITE:GENERIC_READ;
            file=CreateFileW(path.c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);Check(file!=INVALID_HANDLE_VALUE,"successful initial open");
            OVERLAPPED region{};
            if(n==6||n==7){
                lock=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    nullptr,OPEN_EXISTING,0,nullptr);Check(lock!=INVALID_HANDLE_VALUE,"lock owner open");
                Check(LockFileEx(lock,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&region)!=0,"byte lock");
            }
            SQ_ARM_REQUEST arm{};arm.Version=1;arm.Count=1;arm.Handles[0]=reinterpret_cast<ULONGLONG>(file);
            Command(device,SQ_ARM,&arm,sizeof(arm),nullptr,0);armed=true;
            SQ_TOKEN effectiveTruth=ownerTruth;ULONG state=1;
            if(n<8){Check(SetThreadToken(nullptr,imp)!=0,"impersonate after successful open");impersonating=true;effectiveTruth=Truth(imp);state=2;}
            IO_STATUS_BLOCK io{};LARGE_INTEGER offset{};char data='X';LONG status=0;ULONG operation=0,kind=0;
            if(n==0||n==6||n==8){operation=SQ_SYSCALL_READ;status=read(file,nullptr,nullptr,nullptr,&io,&data,1,&offset,nullptr);}
            else if(n==1||n==2||n==7){operation=SQ_SYSCALL_WRITE;if(n==2)offset.QuadPart=-1;status=write(file,nullptr,nullptr,nullptr,&io,&data,1,&offset,nullptr);}
            else if(n==3){operation=SQ_SYSCALL_SET_INFORMATION;kind=20;LARGE_INTEGER end{};status=set(file,&io,&end,sizeof(end),kind);}
            else if(n==4){
                operation=SQ_SYSCALL_SET_INFORMATION;kind=10;
                std::wstring target=L"\\??\\"+root+L"\\renamed.txt";
                size_t bytes=FIELD_OFFSET(RenameInfo,Name)+target.size()*sizeof(WCHAR);
                std::vector<unsigned char> buffer(bytes);auto rename=reinterpret_cast<RenameInfo*>(buffer.data());
                rename->Length=static_cast<ULONG>(target.size()*sizeof(WCHAR));memcpy(rename->Name,target.data(),rename->Length);
                status=set(file,&io,rename,static_cast<ULONG>(bytes),kind);
            }else{operation=SQ_SYSCALL_SET_INFORMATION;kind=13;BOOLEAN remove=TRUE;status=set(file,&io,&remove,sizeof(remove),kind);}
            if(impersonating){Check(RevertToSelf()!=0,"revert after actual native return");impersonating=false;}
#ifdef SQ_MANAGED_PRODUCER
            ExpectedOperation evidence{1,sizeof(ExpectedOperation),birthId,GetCurrentProcessId(),GetCurrentThreadId(),operation,kind,state,status,
                operation==SQ_SYSCALL_SET_INFORMATION?0U:1U,0,ownerTruth,effectiveTruth};
#elif defined(SQ_DTRACE_CONTEXT_TEST)
            SQ_DTRACE_CONTEXT_RECORD entry{},returned{};
            Command(device,SQ_DTRACE_CONTEXT,nullptr,0,&entry,sizeof(entry));
            Command(device,SQ_DTRACE_CONTEXT,nullptr,0,&returned,sizeof(returned));
            Command(device,SQ_DISARM,nullptr,0,nullptr,0);armed=false;
            struct {SQ_DTRACE_CONTEXT_RECORD Entry,Returned;SQ_TOKEN OwnerTruth,EffectiveTruth;} evidence{entry,returned,ownerTruth,effectiveTruth};
#else
            SQ_SYSCALL_RECORD record{};
#ifdef SQ_INTAKE_TEST
            SQ_SOURCE_INFO source{};Command(device,SQ_SOURCE,nullptr,0,&source,sizeof(source));
            Check(source.Version==1&&source.Size==sizeof(source)&&source.Queued==1&&source.Lost==0,"intake source health");
            Command(device,SQ_PEEK,nullptr,0,&record,sizeof(record));
            SQ_SYSCALL_RECORD second{};Command(device,SQ_PEEK,nullptr,0,&second,sizeof(second));
            Check(memcmp(&record,&second,sizeof(record))==0,"peek preserves exact native head");
            SQ_INTAKE_KEY key{1,sizeof(SQ_INTAKE_KEY),source.Instance,record.Sequence};
            SQ_TARGET_REPLY target{};Command(device,SQ_TARGET,&key,sizeof(key),&target,sizeof(target));
            Check(target.Version==1&&target.Size==sizeof(target)&&target.Sequence==record.Sequence&&
                memcmp(&target.Instance,&source.Instance,sizeof(GUID))==0&&target.NameStatus==0&&target.NameBytes>0&&target.NameBytes<=3070,"retained target query identity");
            auto wrong=key;wrong.Sequence++;DWORD ignored=0;
            Check(DeviceIoControl(device,SQ_ACK,&wrong,sizeof(wrong),nullptr,0,&ignored,nullptr)==0,"foreign sequence ACK rejected");
            Command(device,SQ_PEEK,nullptr,0,&second,sizeof(second));Check(memcmp(&record,&second,sizeof(record))==0,"wrong ACK retains head");
            struct {SQ_SOURCE_INFO Source;SQ_TARGET_REPLY Target;SQ_SYSCALL_RECORD Record;} intake{source,target,record};
            HANDLE transport=CreateFileW((root+LR"(\native-intake.bin)").c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
            Check(transport!=INVALID_HANDLE_VALUE,"open immutable intake fixture output");DWORD intakeWritten=0;
            bool saved=WriteFile(transport,&intake,sizeof(intake),&intakeWritten,nullptr)!=0&&intakeWritten==sizeof(intake)&&FlushFileBuffers(transport)!=0;
            CloseHandle(transport);Check(saved,"flush native intake record before ACK");Command(device,SQ_ACK,&key,sizeof(key),nullptr,0);
            SQ_SOURCE_INFO drained{};Command(device,SQ_SOURCE,nullptr,0,&drained,sizeof(drained));Check(drained.Queued==0&&drained.Lost==0,"exact ACK drains one record");
#else
            Command(device,SQ_RECORD,nullptr,0,&record,sizeof(record));
#endif
            struct {SQ_SYSCALL_RECORD Observed;SQ_TOKEN OwnerTruth,EffectiveTruth;} evidence{record,ownerTruth,effectiveTruth};
#endif
            DWORD written=0;Check(WriteFile(raw,&evidence,sizeof(evidence),&written,nullptr)!=0&&written==sizeof(evidence),"preserve raw token/operation truth pair");
            LONG expected=n<6?static_cast<LONG>(0xC0000022U):n<8?static_cast<LONG>(0xC0000054U):0;
#ifdef SQ_MANAGED_PRODUCER
            bool matched=status==expected;
            // Wait for the independently running managed receiver to commit and
            // acknowledge. A timeout fails the test without consuming the queue.
            bool drained=false;const ULONGLONG deadline=GetTickCount64()+60000;
            do{SQ_SOURCE_INFO source{};Command(device,SQ_SOURCE,nullptr,0,&source,sizeof(source));
                Check(source.Lost==0,"managed producer source has no lost records");
                if(source.Queued==0){drained=true;break;}Sleep(20);
            }while(GetTickCount64()<deadline);
            matched=matched&&drained;Command(device,SQ_DISARM,nullptr,0,nullptr,0);armed=false;
#elif defined(SQ_DTRACE_CONTEXT_TEST)
            bool matched=status==expected&&entry.Version==1&&returned.Version==1&&
                entry.Size==sizeof(entry)&&returned.Size==sizeof(returned)&&entry.Stage==1&&returned.Stage==2&&
                entry.Operation==operation&&returned.Operation==operation&&
                entry.ProcessId==GetCurrentProcessId()&&returned.ProcessId==GetCurrentProcessId()&&
                entry.ThreadId==GetCurrentThreadId()&&returned.ThreadId==GetCurrentThreadId()&&
                entry.ProcessBirth==birthId&&returned.ProcessBirth==birthId&&
                entry.Arguments[0]==reinterpret_cast<ULONGLONG>(file)&&
                static_cast<LONG>(returned.Arguments[0])==status&&entry.Sequence>priorSequence&&
                returned.Sequence>entry.Sequence&&returned.Monotonic>=entry.Monotonic;
            priorSequence=returned.Sequence;
#else
            bool matched=status==expected&&record.Version==1&&record.Size==sizeof(record)&&
                record.ReturnStatus==status&&record.ProcessId==GetCurrentProcessId()&&
                record.ThreadId==GetCurrentThreadId()&&record.ProcessBirth==birthId&&
                record.TargetHandle==reinterpret_cast<ULONGLONG>(file)&&record.Operation==operation&&
                record.InformationClass==kind&&record.ImpersonationState==state&&
                record.AttributionStatus==0&&record.FileObjectStatus==0&&record.CaptureIrql==0&&
                record.RequestorMode==1&&Same(record.Owner,ownerTruth)&&Same(record.Effective,effectiveTruth)&&
                record.Sequence>priorSequence&&record.ReturnUtc>=record.EntryUtc&&
                record.ReturnMonotonic>=record.EntryMonotonic;
            priorSequence=record.Sequence;
            Command(device,SQ_DISARM,nullptr,0,nullptr,0);armed=false;
#endif
            if(lock!=INVALID_HANDLE_VALUE){Check(UnlockFileEx(lock,0,1,0,&region)!=0,"unlock");CloseHandle(lock);lock=INVALID_HANDLE_VALUE;}
            CloseHandle(file);file=INVALID_HANDLE_VALUE;
            HANDLE verify=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                nullptr,OPEN_EXISTING,0,nullptr);Check(verify!=INVALID_HANDLE_VALUE,"target still exists");
            char actual[4]{};DWORD done=0;bool unchanged=ReadFile(verify,actual,4,&done,nullptr)!=0&&done==4&&memcmp(actual,"SQ01",4)==0;
            LARGE_INTEGER size{};unchanged=unchanged&&GetFileSizeEx(verify,&size)!=0&&size.QuadPart==4;CloseHandle(verify);
            matched=matched&&unchanged;Command(device,SQ_HEALTH,nullptr,0,&health,sizeof(health));
            matched=matched&&health.Queued==0&&health.Lost==0;
#ifdef SQ_MANAGED_PRODUCER
            printf("{\"Case\":\"%s\",\"Passed\":%s,\"Pid\":%lu,\"Tid\":%lu,\"Birth\":%llu,\"NativeStatus\":\"0x%08lX\","
                "\"OwnerSid\":\"%s\",\"EffectiveSid\":\"%s\",\"ImpersonationState\":%lu,\"ManagedAcknowledged\":%s,\"TargetUnchanged\":%s}\n",
                names[n],matched?"true":"false",GetCurrentProcessId(),GetCurrentThreadId(),birthId,static_cast<unsigned long>(status),
                Sid(ownerTruth).c_str(),Sid(effectiveTruth).c_str(),state,drained?"true":"false",unchanged?"true":"false");
#elif defined(SQ_DTRACE_CONTEXT_TEST)
            SQ_DTRACE_HEALTH_RECORD dh{};Command(device,SQ_DTRACE_HEALTH,nullptr,0,&dh,sizeof(dh));
            matched=matched&&dh.Queued==0&&dh.Lost==0;
            printf("{\"Case\":\"%s\",\"Passed\":%s,\"Pid\":%lu,\"Tid\":%lu,\"Birth\":%llu,"
                "\"NativeStatus\":\"0x%08lX\",\"EntryIrql\":%lu,\"ReturnIrql\":%lu,"
                "\"EntryInterruptsEnabled\":%lu,\"ReturnInterruptsEnabled\":%lu,"
                "\"EntryAllApcsDisabled\":%lu,\"ReturnAllApcsDisabled\":%lu,"
                "\"ExpectedInformationClass\":%lu,\"ExpectedImpersonationState\":%lu,"
                "\"ExpectedOwnerSid\":\"%s\",\"ExpectedEffectiveSid\":\"%s\","
                "\"TokenCaptureEstablished\":false,\"TargetUnchanged\":%s}\n",names[n],matched?"true":"false",
                GetCurrentProcessId(),GetCurrentThreadId(),birthId,static_cast<unsigned long>(status),
                entry.Irql,returned.Irql,entry.InterruptsEnabled,returned.InterruptsEnabled,
                entry.AllApcsDisabled,returned.AllApcsDisabled,kind,state,Sid(ownerTruth).c_str(),Sid(effectiveTruth).c_str(),unchanged?"true":"false");
#else
            printf("{\"Case\":\"%s\",\"Passed\":%s,\"Pid\":%lu,\"Tid\":%lu,"
                "\"Birth\":%llu,\"NativeStatus\":\"0x%08lX\",\"Sequence\":%llu,"
                "\"OwnerSid\":\"%s\",\"EffectiveSid\":\"%s\",\"ImpersonationState\":%lu,"
                "\"FullTokenMatch\":%s,\"TargetUnchanged\":%s}\n",names[n],matched?"true":"false",
                GetCurrentProcessId(),GetCurrentThreadId(),birthId,static_cast<unsigned long>(status),
                record.Sequence,Sid(record.Owner).c_str(),Sid(record.Effective).c_str(),record.ImpersonationState,
                Same(record.Owner,ownerTruth)&&Same(record.Effective,effectiveTruth)?"true":"false",unchanged?"true":"false");
#endif
            fflush(stdout);Check(matched,"native status/token/identity/filesystem mismatch");passed++;
        }
#ifdef SQ_DTRACE_CONTEXT_TEST
        SQ_DTRACE_HEALTH_RECORD finalContext{};Command(device,SQ_DTRACE_HEALTH,nullptr,0,&finalContext,sizeof(finalContext));
        printf("{\"Complete\":true,\"Passed\":%u,\"Lost\":%llu,\"CentralIntegrated\":false,"
            "\"ContextOnly\":true,\"TokenCaptureEstablished\":false}\n",passed,finalContext.Lost);
#else
        printf("{\"Complete\":true,\"Passed\":%u,\"Lost\":%llu,\"CentralIntegrated\":false}\n",passed,health.Lost);
#endif
        Check(FlushFileBuffers(raw)!=0,"flush raw evidence");CloseHandle(raw);raw=INVALID_HANDLE_VALUE;
        CloseHandle(owner);CloseHandle(imp);CloseHandle(primary);CloseHandle(device);return 0;
    }catch(const std::exception& ex){
        DWORD error=GetLastError();if(impersonating)RevertToSelf();
        if(armed&&device!=INVALID_HANDLE_VALUE){DWORD done=0;DeviceIoControl(device,SQ_DISARM,nullptr,0,nullptr,0,&done,nullptr);}
        if(lock!=INVALID_HANDLE_VALUE)CloseHandle(lock);if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
        if(owner)CloseHandle(owner);if(imp)CloseHandle(imp);if(primary)CloseHandle(primary);
        if(device!=INVALID_HANDLE_VALUE)CloseHandle(device);
        if(raw!=INVALID_HANDLE_VALUE)CloseHandle(raw);
        fprintf(stderr,"Native qualification failed: %s; Win32=%lu\n",ex.what(),error);return 1;
    }
}
