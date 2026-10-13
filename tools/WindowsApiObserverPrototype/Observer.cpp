// Isolated owned-process experiment. Never a kernel-authoritative observation.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <detours.h>
#include <string>
#include <sstream>
#include <iomanip>

using FileIo = NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
using SetInfo = NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
static FileIo Read,Write;
static SetInfo Set;
static thread_local bool Inside;
static SRWLOCK LogLock=SRWLOCK_INIT;
static volatile LONG64 Sequence;
static DWORD HookStatus=ERROR_NOT_READY;
static DWORD ReadService=0xffffffff;

static std::string Hex(ULONGLONG v) { std::ostringstream s; s<<std::uppercase<<std::hex<<std::setw(16)<<std::setfill('0')<<v; return s.str(); }
static ULONGLONG Id(const LUID& v) { return ((ULONGLONG)(DWORD)v.HighPart<<32)|v.LowPart; }
static ULONGLONG Time(const FILETIME& v) { return ((ULONGLONG)v.dwHighDateTime<<32)|v.dwLowDateTime; }
static std::string Json(const std::wstring& v) {
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,v.data(),(int)v.size(),nullptr,0,nullptr,nullptr);
    if(n==0&&!v.empty())return "null";
    std::string utf(n,0),s="\""; if(n)WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,v.data(),(int)v.size(),&utf[0],n,nullptr,nullptr);
    for(unsigned char c:utf){if(c=='"'||c=='\\'){s+='\\';s+=(char)c;}else if(c<32){char b[7];sprintf_s(b,"\\u%04x",c);s+=b;}else s+=(char)c;}return s+'"';
}
static std::wstring Env(const wchar_t* name) { wchar_t b[32768];DWORD n=GetEnvironmentVariableW(name,b,32768);return n&&n<32768?std::wstring(b,n):L""; }
struct Token {
    bool Valid=false; DWORD Error=ERROR_NOT_READY; TOKEN_STATISTICS Statistics={};
    DWORD Session=0,Integrity=0,Elevation=0;std::wstring Sid;
};
static Token Snapshot(HANDLE handle) {
    Token t; DWORD n=0; BYTE b[4096];
    if(!GetTokenInformation(handle,TokenStatistics,&t.Statistics,sizeof(t.Statistics),&n)){t.Error=GetLastError();return t;}
    if(!GetTokenInformation(handle,TokenUser,b,sizeof(b),&n)){t.Error=GetLastError();return t;}
    LPWSTR sid=nullptr; if(!ConvertSidToStringSidW(((TOKEN_USER*)b)->User.Sid,&sid)){t.Error=GetLastError();return t;}t.Sid=sid;LocalFree(sid);
    if(!GetTokenInformation(handle,TokenSessionId,&t.Session,sizeof(t.Session),&n)){t.Error=GetLastError();return t;}
    if(!GetTokenInformation(handle,TokenIntegrityLevel,b,sizeof(b),&n)){t.Error=GetLastError();return t;}
    PSID label=((TOKEN_MANDATORY_LABEL*)b)->Label.Sid;t.Integrity=*GetSidSubAuthority(label,*GetSidSubAuthorityCount(label)-1);
    TOKEN_ELEVATION elevation={};if(!GetTokenInformation(handle,TokenElevation,&elevation,sizeof(elevation),&n)){t.Error=GetLastError();return t;}t.Elevation=elevation.TokenIsElevated;
    TOKEN_STATISTICS end={};if(!GetTokenInformation(handle,TokenStatistics,&end,sizeof(end),&n)){t.Error=GetLastError();return t;}
    if(Id(end.TokenId)!=Id(t.Statistics.TokenId)||Id(end.ModifiedId)!=Id(t.Statistics.ModifiedId)){t.Error=ERROR_RETRY;return t;}t.Valid=true;t.Error=0;return t;
}
static std::string TokenJson(const Token& t) {
    std::ostringstream s;s<<"{\"State\":\""<<(t.Valid?"captured":"unavailable")<<"\",\"Error\":"<<t.Error;
    if(t.Valid){s<<",\"Sid\":"<<Json(t.Sid)<<",\"TokenId\":\""<<Hex(Id(t.Statistics.TokenId))<<"\",\"AuthenticationId\":\""<<Hex(Id(t.Statistics.AuthenticationId))<<"\",\"ModifiedId\":\""<<Hex(Id(t.Statistics.ModifiedId))<<"\",\"Type\":"<<t.Statistics.TokenType<<",\"ImpersonationLevel\":";
        if(t.Statistics.TokenType==TokenImpersonation)s<<t.Statistics.ImpersonationLevel;else s<<"null";
        s<<",\"SessionId\":"<<t.Session<<",\"IntegrityRid\":"<<t.Integrity<<",\"Elevated\":"<<(t.Elevation?"true":"false");}else s<<",\"Sid\":null";
    return s.str()+'}';
}
struct Context {
    bool Watched=false,Impersonating=false,Known=false; std::wstring Path; Token Primary,Effective;
    HANDLE ProcessToken=nullptr,ThreadToken=nullptr;FILETIME Start={};LARGE_INTEGER Clock={};
    Context(HANDLE file) {
        auto watched=Env(L"SQ_OBSERVER_TARGET");if(watched.empty())return;
        wchar_t name[32768];DWORD n=GetFinalPathNameByHandleW(file,name,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        if(!n||n>=32768)return;Path.assign(name,n);if(Path.rfind(L"\\\\?\\",0)==0)Path=Path.substr(4);
        if(_wcsicmp(Path.c_str(),watched.c_str()))return;Watched=true;
        FILETIME end,kernel,user;if(!GetProcessTimes(GetCurrentProcess(),&Start,&end,&kernel,&user))Start={};
        QueryPerformanceCounter(&Clock);
        // Windows 8/Server 2012+ query-only pseudo-handle still identifies this
        // process's primary token while the calling thread impersonates a user
        // who cannot open the SYSTEM process token through its object DACL.
        ProcessToken=GetCurrentProcessToken();Primary=Snapshot(ProcessToken);
        if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&ThreadToken)){Impersonating=true;Known=true;Effective=Snapshot(ThreadToken);}
        else {DWORD e=GetLastError();if(e==ERROR_NO_TOKEN){Known=true;Effective=Primary;}else Effective.Error=e;}
    }
    ~Context(){if(ThreadToken)CloseHandle(ThreadToken);}
};
static void Emit(Context& c,const char* op,ULONG info,NTSTATUS status) {
    if(!c.Watched)return;
    // Detect observable changes across the call. These are two observations,
    // not an atomic guarantee about all security checks inside Windows.
    bool stable=c.Primary.Valid&&c.Effective.Valid;DWORD n;
    TOKEN_STATISTICS end={};if(!c.ProcessToken||!GetTokenInformation(c.ProcessToken,TokenStatistics,&end,sizeof(end),&n)||Id(end.TokenId)!=Id(c.Primary.Statistics.TokenId)||Id(end.ModifiedId)!=Id(c.Primary.Statistics.ModifiedId))stable=false;
    HANDLE current=nullptr;Token after;bool afterKnown=false,afterImpersonating=false;
    if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&current)){afterKnown=true;afterImpersonating=true;after=Snapshot(current);CloseHandle(current);}
    else if(GetLastError()==ERROR_NO_TOKEN){afterKnown=true;if(c.ProcessToken)after=Snapshot(c.ProcessToken);}
    if(!c.Known||!afterKnown||afterImpersonating!=c.Impersonating||!after.Valid||Id(after.Statistics.TokenId)!=Id(c.Effective.Statistics.TokenId)||Id(after.Statistics.ModifiedId)!=Id(c.Effective.Statistics.ModifiedId))stable=false;
    FILETIME wall;GetSystemTimeAsFileTime(&wall);LARGE_INTEGER frequency;QueryPerformanceFrequency(&frequency);
    std::ostringstream s;s<<"{\"SchemaVersion\":1,\"Source\":\"Windows API observer prototype\",\"Authority\":\"in-process-supplemental\",\"HookStatus\":"<<HookStatus<<",\"Pid\":"<<GetCurrentProcessId()<<",\"ThreadId\":"<<GetCurrentThreadId()<<",\"ProcessCreatedFileTime\":"<<Time(c.Start)<<",\"WallFileTime\":"<<Time(wall)<<",\"Monotonic\":"<<c.Clock.QuadPart<<",\"MonotonicFrequency\":"<<frequency.QuadPart<<",\"Sequence\":"<<InterlockedIncrement64(&Sequence)<<",\"Operation\":\""<<op<<"\",\"InformationClass\":"<<info<<",\"Path\":"<<Json(c.Path)<<",\"NtStatus\":\"0x"<<Hex((DWORD)status).substr(8)<<"\",\"Pending\":"<<(status==0x103?"true":"false")<<",\"TokenObservationStableAcrossCall\":"<<(stable?"true":"false")<<",\"Impersonating\":";
    if(c.Known)s<<(c.Impersonating?"true":"false");else s<<"null";
    s<<",\"ProcessPrimary\":"<<TokenJson(c.Primary)<<",\"ThreadEffective\":"<<TokenJson(c.Effective)<<",\"AfterThreadEffective\":"<<TokenJson(after)<<"}\n";
    auto log=Env(L"SQ_OBSERVER_LOG");if(log.empty())return;auto bytes=s.str();AcquireSRWLockExclusive(&LogLock);
    HANDLE f=CreateFileW(log.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f!=INVALID_HANDLE_VALUE){DWORD written;WriteFile(f,bytes.data(),(DWORD)bytes.size(),&written,nullptr);FlushFileBuffers(f);CloseHandle(f);}ReleaseSRWLockExclusive(&LogLock);
}
static NTSTATUS NTAPI OnRead(HANDLE f,HANDLE e,PIO_APC_ROUTINE a,PVOID c,PIO_STATUS_BLOCK io,PVOID b,ULONG n,PLARGE_INTEGER o,PULONG k){
    if(Inside)return Read(f,e,a,c,io,b,n,o,k);Inside=true;bool called=false;NTSTATUS result=0;DWORD last=GetLastError();
    try{Context ctx(f);SetLastError(last);result=Read(f,e,a,c,io,b,n,o,k);called=true;last=GetLastError();Emit(ctx,"NtReadFile",0,result);}catch(...){if(!called){SetLastError(last);result=Read(f,e,a,c,io,b,n,o,k);last=GetLastError();}}
    Inside=false;SetLastError(last);return result;
}
static NTSTATUS NTAPI OnWrite(HANDLE f,HANDLE e,PIO_APC_ROUTINE a,PVOID c,PIO_STATUS_BLOCK io,PVOID b,ULONG n,PLARGE_INTEGER o,PULONG k){
    if(Inside)return Write(f,e,a,c,io,b,n,o,k);Inside=true;bool called=false;NTSTATUS result=0;DWORD last=GetLastError();
    try{Context ctx(f);SetLastError(last);result=Write(f,e,a,c,io,b,n,o,k);called=true;last=GetLastError();Emit(ctx,"NtWriteFile",0,result);}catch(...){if(!called){SetLastError(last);result=Write(f,e,a,c,io,b,n,o,k);last=GetLastError();}}
    Inside=false;SetLastError(last);return result;
}
static NTSTATUS NTAPI OnSet(HANDLE f,PIO_STATUS_BLOCK io,PVOID b,ULONG n,FILE_INFORMATION_CLASS k){
    if(Inside)return Set(f,io,b,n,k);Inside=true;bool called=false;NTSTATUS result=0;DWORD last=GetLastError();
    try{Context ctx(f);SetLastError(last);result=Set(f,io,b,n,k);called=true;last=GetLastError();Emit(ctx,"NtSetInformationFile",(ULONG)k,result);}catch(...){if(!called){SetLastError(last);result=Set(f,io,b,n,k);last=GetLastError();}}
    Inside=false;SetLastError(last);return result;
}
extern "C" __declspec(dllexport) void __cdecl ObserverMarker(){}
// Negative-test support only: read the service identifier before hooking the
// unmodified ntdll entry. Refuse any unrecognized entry layout.
extern "C" __declspec(dllexport) DWORD __cdecl ObserverNtReadService(){return ReadService;}
BOOL WINAPI DllMain(HINSTANCE,DWORD reason,LPVOID) {
    if(DetourIsHelperProcess())return TRUE;
    if(reason==DLL_PROCESS_ATTACH){DetourRestoreAfterWith();auto nt=GetModuleHandleW(L"ntdll.dll");
        Read=(FileIo)GetProcAddress(nt,"NtReadFile");Write=(FileIo)GetProcAddress(nt,"NtWriteFile");Set=(SetInfo)GetProcAddress(nt,"NtSetInformationFile");
        if(!Read||!Write||!Set)return FALSE;
        const BYTE* entry=(const BYTE*)Read;
        if(entry[0]==0x4c&&entry[1]==0x8b&&entry[2]==0xd1&&entry[3]==0xb8)CopyMemory(&ReadService,entry+4,sizeof(ReadService));
        LONG status=DetourTransactionBegin();if(status)return FALSE;status=DetourUpdateThread(GetCurrentThread());
        if(!status)status=DetourAttach(&(PVOID&)Read,OnRead);if(!status)status=DetourAttach(&(PVOID&)Write,OnWrite);if(!status)status=DetourAttach(&(PVOID&)Set,OnSet);
        if(status){DetourTransactionAbort();return FALSE;}HookStatus=DetourTransactionCommit();if(HookStatus)return FALSE;
    }return TRUE;
}
