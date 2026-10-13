#include <windows.h>
#include <winioctl.h>
#include <sddl.h>
#include <stdio.h>
#include "CallbackTokenLabProtocol.h"
static void Check(bool value,const char* step){if(!value){fprintf(stderr,"%s error %lu\n",step,GetLastError());ExitProcess(1);}}
// Optional direct scheduled-executable output. CREATE_NEW preserves prior
// results; no PowerShell worker or inherited console is needed under SYSTEM.
static void RedirectLog(const wchar_t* path,int destination){
 HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 Check(file!=INVALID_HANDLE_VALUE,"create owned log");
 CloseHandle(file);
 FILE* opened=nullptr;
 // Append to the file just created exclusively. This also initializes a CRT
 // stream when the scheduled executable has no inherited console descriptor.
 Check(_wfreopen_s(&opened,path,L"a",destination==1?stdout:stderr)==0&&opened,"redirect owned log");
}
static bool Equal(LUID a,LUID b){return a.LowPart==b.LowPart&&a.HighPart==b.HighPart;}
static TOKEN_STATISTICS Stats(HANDLE token){TOKEN_STATISTICS result{};DWORD bytes=0;Check(GetTokenInformation(token,TokenStatistics,&result,sizeof(result),&bytes)!=0,"statistics");return result;}
static SQ_CB_REPLY Call(HANDLE device,DWORD code,SQ_CB_ARM_INPUT* input=nullptr){SQ_CB_REPLY result{};DWORD bytes=0;Check(DeviceIoControl(device,code,input,input?sizeof(*input):0,&result,sizeof(result),&bytes,nullptr)!=0,"ioctl");Check(bytes==sizeof(result)&&result.Version==2&&result.Size==sizeof(result),"protocol");return result;}
int wmain(int count,wchar_t** args){
 if(count!=2&&count!=4)return 2;
 if(count==4){RedirectLog(args[2],1);RedirectLog(args[3],2);setvbuf(stdout,nullptr,_IONBF,0);setvbuf(stderr,nullptr,_IONBF,0);}
 HANDLE device=CreateFileW(L"\\\\.\\SqCallbackTokenLab",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);Check(device!=INVALID_HANDLE_VALUE,"device");
 HANDLE sender=CreateFileW(L"\\\\.\\SqCallbackPagingSender",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);Check(sender!=INVALID_HANDLE_VALUE,"paging sender");
 HANDLE file=CreateFileW(args[1],GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);Check(file!=INVALID_HANDLE_VALUE,"owned target");
 DWORD bytes=0;char preparation[4096]{};memcpy(preparation,"test",4);Check(WriteFile(file,preparation,sizeof(preparation),&bytes,nullptr)!=0&&bytes==sizeof(preparation),"prepare target");Check(FlushFileBuffers(file)!=0,"flush owned target before paging read");
 HANDLE primary=nullptr,copy=nullptr;Check(LogonUserW(L"LocalService",L"NT AUTHORITY",L"",LOGON32_LOGON_SERVICE,LOGON32_PROVIDER_DEFAULT,&primary)!=0,"LocalService logon");Check(DuplicateTokenEx(primary,TOKEN_ALL_ACCESS,nullptr,SecurityImpersonation,TokenImpersonation,&copy)!=0,"duplicate");
 FILETIME start,exit,kernel,user;Check(GetProcessTimes(GetCurrentProcess(),&start,&exit,&kernel,&user)!=0,"process birth");ULONGLONG birth=((ULONGLONG)start.dwHighDateTime<<32)|start.dwLowDateTime;
 for(DWORD mode=0;mode<3;mode++)for(int i=0;i<32;i++){
  SQ_CB_ARM_INPUT arm{mode,0,(ULONGLONG)(ULONG_PTR)file};
  SetFilePointer(file,0,nullptr,FILE_BEGIN);Call(device,SQ_CB_ARM,&arm);Check(SetThreadToken(nullptr,copy)!=0,"impersonate");auto truth=Stats(copy);char data[4];
  if(mode==2){ULONGLONG handle=(ULONGLONG)(ULONG_PTR)file;SQ_CB_SENDER_REPLY generated{};BOOL submitted=DeviceIoControl(sender,SQ_CB_SENDER_READ,&handle,sizeof(handle),&generated,sizeof(generated),&bytes,nullptr);DWORD sendError=GetLastError();bool valid=submitted&&bytes==sizeof(generated)&&generated.Version==1&&generated.Size==sizeof(generated)&&generated.SubmitIrql==1&&generated.OperationStatus==0&&generated.BytesRead==4096&&generated.FirstByte==(ULONG)'t';if(!valid)fprintf(stderr,"paging reply submitted=%ld error=%lu returned=%lu version=%lu size=%lu irql=%lu status=0x%08lX bytes=%llu first=%lu\n",submitted,sendError,bytes,generated.Version,generated.Size,generated.SubmitIrql,(ULONG)generated.OperationStatus,generated.BytesRead,generated.FirstByte);Check(valid,"Filter Manager paging read");}
  else Check(ReadFile(file,data,sizeof(data),&bytes,nullptr)!=0&&bytes==4,"owned read");
  Check(RevertToSelf()!=0,"revert");auto peek=Call(device,SQ_CB_PEEK);
  if(!peek.Completed){printf("{\"case\":\"unavailable_callback_diagnostic\",\"mode\":%lu,\"target_callbacks\":%llu,\"null_thread_callbacks\":%llu,\"other_thread_callbacks\":%llu,\"last_callback_tid\":%llu,\"last_callback_irql\":%lu,\"expected_tid\":%lu,\"armed_read_callbacks\":%llu,\"owner_read_callbacks\":%llu,\"target_name_callbacks\":%llu,\"last_owner_same_device\":%lu,\"last_owner_same_name\":%lu,\"last_owner_name_bytes\":%lu,\"armed_name_bytes\":%lu}\n",mode,peek.TargetCallbacks,peek.NullThreadCallbacks,peek.OtherThreadCallbacks,peek.LastCallbackTid,peek.LastCallbackIrql,GetCurrentThreadId(),peek.ArmedReadCallbacks,peek.OwnerReadCallbacks,peek.TargetNameCallbacks,peek.LastOwnerSameDevice,peek.LastOwnerSameName,peek.LastOwnerNameBytes,peek.ArmedNameBytes);Check(false,"target callback attribution unavailable");}
  auto result=Call(device,SQ_CB_QUERY);
  Check(result.Completed==1&&result.OperationStatus==0&&result.UserStatus==0&&result.StatisticsStatus==0&&result.QueryIrql==0&&result.Pid==GetCurrentProcessId()&&result.Tid==GetCurrentThreadId()&&result.ProcessBirth==birth&&result.Impersonating==1&&Equal(result.TokenId,truth.TokenId)&&Equal(result.ModifiedId,truth.ModifiedId)&&Equal(result.AuthenticationId,truth.AuthenticationId)&&result.Level==(ULONG)truth.ImpersonationLevel,"actual callback token truth");
  if(mode==2)Check(result.CallbackIrql==1&&result.ReferenceIrql==1&&result.ForcedApc==0,"Filter Manager generated APC callback");
  LPSTR sid=nullptr;Check(result.SidBytes&&ConvertSidToStringSidA((PSID)result.Sid,&sid)!=0&&strcmp(sid,"S-1-5-19")==0,"effective SID");
  printf("{\"case\":\"actual_read_callback\",\"mode\":%lu,\"callback_irql\":%lu,\"reference_irql\":%lu,\"query_irql\":%lu,\"forced_apc_control\":%lu,\"pid\":%llu,\"tid\":%llu,\"process_birth\":%llu,\"effective_sid\":\"%s\",\"token_id_high\":%ld,\"token_id_low\":%lu,\"modified_id_high\":%ld,\"modified_id_low\":%lu,\"status\":%ld,\"callbacks\":%llu,\"metadata_timing\":\"later_query_of_entry_referenced_token\"}\n",mode,result.CallbackIrql,result.ReferenceIrql,result.QueryIrql,result.ForcedApc,result.Pid,result.Tid,result.ProcessBirth,sid,result.TokenId.HighPart,result.TokenId.LowPart,result.ModifiedId.HighPart,result.ModifiedId.LowPart,result.OperationStatus,result.Callbacks);LocalFree(sid);

 }
 // A non-impersonating read must explicitly report no thread token, rather
 // than misrepresenting the SYSTEM process owner's primary as impersonation.
 SQ_CB_ARM_INPUT arm{0,0,(ULONGLONG)(ULONG_PTR)file};SetFilePointer(file,0,nullptr,FILE_BEGIN);Call(device,SQ_CB_ARM,&arm);char data[4];Check(ReadFile(file,data,sizeof(data),&bytes,nullptr)!=0,"primary read");auto absent=Call(device,SQ_CB_QUERY);Check(absent.Impersonating==0&&absent.UserStatus<0&&absent.SidBytes==0,"no impersonation control");
 CloseHandle(sender);CloseHandle(file);CloseHandle(device);CloseHandle(copy);CloseHandle(primary);
 printf("{\"complete\":true,\"actual_read_cases\":96,\"filter_manager_apc_cases\":32,\"no_impersonation_control\":true,\"production_integrated\":false,\"full_callback_coverage\":false}\n");return 0;
}
