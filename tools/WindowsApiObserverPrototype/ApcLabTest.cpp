#include <windows.h>
#include <winioctl.h>
#include <sddl.h>
#include <stdio.h>
#include "ApcLabProtocol.h"
static void Check(bool ok,const char* step){if(!ok){fprintf(stderr,"%s error %lu\n",step,GetLastError());ExitProcess(1);}}
static TOKEN_STATISTICS Stats(HANDLE token){TOKEN_STATISTICS s{};DWORD n=0;Check(GetTokenInformation(token,TokenStatistics,&s,sizeof(s),&n)!=0,"statistics");return s;}
static bool Equal(LUID a,LUID b){return a.LowPart==b.LowPart&&a.HighPart==b.HighPart;}
static SQ_LAB_REPLY Call(HANDLE device,DWORD code){SQ_LAB_REPLY r{};DWORD n=0;Check(DeviceIoControl(device,code,nullptr,0,&r,sizeof(r),&n,nullptr)!=0,"ioctl");Check(n==sizeof(r)&&r.Version==1&&r.Size==sizeof(r),"protocol");return r;}
static void Release(HANDLE device){DWORD n=0;Check(DeviceIoControl(device,SQ_RELEASE,nullptr,0,nullptr,0,&n,nullptr)!=0,"release");}
static void Row(const char* name,const SQ_LAB_REPLY& r,bool changed){LPSTR sid=nullptr;if(r.SidBytes)Check(ConvertSidToStringSidA((PSID)r.Sid,&sid)!=0,"sid");printf("{\"case\":\"%s\",\"pid\":%llu,\"tid\":%llu,\"reference_irql\":%lu,\"query_irql\":%lu,\"impersonating_at_reference\":%lu,\"sid\":\"%s\",\"user_status\":%ld,\"statistics_status\":%ld,\"token_id_low\":%lu,\"modified_id_low\":%lu,\"modified_after_pin\":%s,\"metadata_timing\":\"deferred_query_not_historical_snapshot\"}\n",name,r.Pid,r.Tid,r.ReferenceIrql,r.QueryIrql,r.Impersonating,sid?sid:"",r.UserStatus,r.StatisticsStatus,r.TokenId.LowPart,r.ModifiedId.LowPart,changed?"true":"false");if(sid)LocalFree(sid);}
int main(){
 HANDLE device=CreateFileW(L"\\\\.\\SqApcTokenLab",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);Check(device!=INVALID_HANDLE_VALUE,"device");
 HANDLE primary=nullptr,copy=nullptr;Check(LogonUserW(L"LocalService",L"NT AUTHORITY",L"",LOGON32_LOGON_SERVICE,LOGON32_PROVIDER_DEFAULT,&primary)!=0,"LocalService logon");
 Check(DuplicateTokenEx(primary,TOKEN_ALL_ACCESS,nullptr,SecurityImpersonation,TokenImpersonation,&copy)!=0,"duplicate");
 for(int i=0;i<64;i++){
  Check(SetThreadToken(nullptr,copy)!=0,"impersonate");auto truth=Stats(copy);auto pin=Call(device,SQ_PIN);Check(pin.ReferenceIrql==1&&pin.Impersonating==1,"APC reference");
  Check(RevertToSelf()!=0,"revert");auto result=Call(device,SQ_QUERY);Check(result.QueryIrql==0&&result.UserStatus==0&&result.StatisticsStatus==0&&Equal(result.TokenId,truth.TokenId)&&Equal(result.ModifiedId,truth.ModifiedId)&&result.Pid==GetCurrentProcessId()&&result.Tid==GetCurrentThreadId(),"retained token truth");
  LPSTR actualSid=nullptr;Check(result.SidBytes&&ConvertSidToStringSidA((PSID)result.Sid,&actualSid)!=0,"LocalService SID");Check(strcmp(actualSid,"S-1-5-19")==0,"LocalService identity");LocalFree(actualSid);Row("pin_revert_query",result,false);Release(device);
 }
 // Holding a reference does not freeze mutable token privileges or ModifiedId.
 Check(SetThreadToken(nullptr,copy)!=0,"impersonate mutation");auto before=Stats(copy);Call(device,SQ_PIN);Check(RevertToSelf()!=0,"revert mutation");
 TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;Check(LookupPrivilegeValueW(nullptr,SE_CHANGE_NOTIFY_NAME,&p.Privileges[0].Luid)!=0,"privilege");p.Privileges[0].Attributes=0;
 SetLastError(0);Check(AdjustTokenPrivileges(copy,FALSE,&p,sizeof(p),nullptr,nullptr)!=0&&GetLastError()==0,"disable duplicate privilege");auto after=Stats(copy);auto mutated=Call(device,SQ_QUERY);
 Check(Equal(mutated.TokenId,before.TokenId)&&Equal(mutated.ModifiedId,after.ModifiedId)&&!Equal(mutated.ModifiedId,before.ModifiedId),"mutation observed later");Row("mutable_token_control",mutated,true);Release(device);
 auto absentPin=Call(device,SQ_PIN);auto absent=Call(device,SQ_QUERY);Check(absentPin.ReferenceIrql==1&&absentPin.Impersonating==0&&absent.UserStatus<0&&absent.StatisticsStatus<0&&absent.SidBytes==0,"no token");Row("no_impersonation",absent,false);Release(device);
 SQ_LAB_REPLY invalid{};DWORD n=0;Check(!DeviceIoControl(device,SQ_PIN,nullptr,0,&invalid,4,&n,nullptr)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER,"short reply rejection");
 Check(SetThreadToken(nullptr,copy)!=0,"impersonate cleanup");Call(device,SQ_PIN);Check(RevertToSelf()!=0,"revert cleanup");CloseHandle(device);
 device=CreateFileW(L"\\\\.\\SqApcTokenLab",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);Check(device!=INVALID_HANDLE_VALUE,"reopen after cleanup");Check(!DeviceIoControl(device,SQ_QUERY,nullptr,0,&invalid,sizeof(invalid),&n,nullptr),"query without pin rejection");CloseHandle(device);CloseHandle(copy);CloseHandle(primary);
 printf("{\"complete\":true,\"retained_token_cases\":64,\"mutation_control\":true,\"unavailable_control\":true,\"cleanup_control\":true,\"full_callback_coverage\":false}\n");return 0;
}
