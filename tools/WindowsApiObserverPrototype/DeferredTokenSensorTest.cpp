#define SQ_DEFERRED_TOKEN_DIAGNOSTIC 1
#include <windows.h>
#include <fltuser.h>
#include <sddl.h>
#include <stdio.h>
#include "../../src/seQuester.WindowsKernel/Protocol.h"
#include "CallbackTokenLabProtocol.h"
static void Check(bool value,const char* step){if(!value){fprintf(stderr,"%s error %lu\n",step,GetLastError());ExitProcess(1);}}
static void Log(const wchar_t* path,FILE* stream){HANDLE h=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,0,nullptr);Check(h!=INVALID_HANDLE_VALUE,"new log");CloseHandle(h);FILE* out=nullptr;Check(_wfreopen_s(&out,path,L"a",stream)==0&&out,"redirect log");setvbuf(stream,nullptr,_IONBF,0);}
static HRESULT Send(HANDLE port,ULONG command,ULONGLONG instance,ULONGLONG sequence,void* output,DWORD size,DWORD* bytes){struct{ULONG Version,Command;ULONGLONG Instance,Sequence;} request{4,command,instance,sequence};return FilterSendMessage(port,&request,sizeof(request),output,size,bytes);}
static void Drain(HANDLE port){for(int i=0;i<4096;i++){SQ_EVENT event{};DWORD bytes=0;if(FAILED(Send(port,SQ_GET_EVENT,0,0,&event,sizeof(event),&bytes)))return;Check(SUCCEEDED(Send(port,SQ_ACK_EVENT,event.Instance,event.Sequence,nullptr,0,&bytes)),"drain ACK");}Check(false,"unbounded queue");}
int wmain(int count,wchar_t** args){
 if(count!=4)return 2;Log(args[2],stdout);Log(args[3],stderr);
 HANDLE file=CreateFileW(args[1],GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);Check(file!=INVALID_HANDLE_VALUE,"owned target");
 char block[4096]{};block[0]='t';DWORD bytes=0;Check(WriteFile(file,block,sizeof(block),&bytes,nullptr)!=0&&bytes==sizeof(block),"prepare target");Check(FlushFileBuffers(file)!=0,"flush target before generated noncached read");
 wchar_t path[SQ_PATH_CHARS]{};DWORD length=GetFinalPathNameByHandleW(file,path,SQ_PATH_CHARS,VOLUME_NAME_NT);Check(length>0&&length<SQ_PATH_CHARS,"native target path");
 HANDLE port=nullptr;Check(SUCCEEDED(FilterConnectCommunicationPort(SQ_PORT_NAME,0,nullptr,0,nullptr,&port)),"private sensor port");
 struct{ULONG Version,Command,Count;WCHAR Path[SQ_PATH_CHARS];} scope{};
 scope.Version=4;scope.Command=SQ_SET_PATHS;scope.Count=1;Check(wcscpy_s(scope.Path,path)==0,"scope length");
 HRESULT scoped=FilterSendMessage(port,&scope,sizeof(scope),nullptr,0,&bytes);if(FAILED(scoped))fprintf(stderr,"set owned scope HRESULT 0x%08lX\n",(ULONG)scoped);Check(SUCCEEDED(scoped),"set owned scope");
 // Warm the name cache without claiming this ordinary read exercises APC.
 SetFilePointer(file,0,nullptr,FILE_BEGIN);Check(ReadFile(file,block,4,&bytes,nullptr)!=0,"name cache read");Drain(port);
 HANDLE sender=CreateFileW(L"\\\\.\\SqCallbackPagingSender",GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);Check(sender!=INVALID_HANDLE_VALUE,"sender device");
 HANDLE primary=nullptr,token=nullptr;Check(LogonUserW(L"LocalService",L"NT AUTHORITY",L"",LOGON32_LOGON_SERVICE,LOGON32_PROVIDER_DEFAULT,&primary)!=0,"LocalService logon");Check(DuplicateTokenEx(primary,TOKEN_ALL_ACCESS,nullptr,SecurityImpersonation,TokenImpersonation,&token)!=0,"impersonation token");
 TOKEN_STATISTICS truth{};Check(GetTokenInformation(token,TokenStatistics,&truth,sizeof(truth),&bytes)!=0,"token truth");
 FILETIME start,exit,kernel,user;Check(GetProcessTimes(GetCurrentProcess(),&start,&exit,&kernel,&user)!=0,"process birth");ULONGLONG birth=((ULONGLONG)start.dwHighDateTime<<32)|start.dwLowDateTime;
 for(int i=0;i<33;i++){
  if(i<32)Check(SetThreadToken(nullptr,token)!=0,"impersonate");
  ULONGLONG handle=(ULONGLONG)(ULONG_PTR)file;SQ_CB_SENDER_REPLY generated{};
  Check(DeviceIoControl(sender,SQ_CB_SENDER_READ,&handle,sizeof(handle),&generated,sizeof(generated),&bytes,nullptr)!=0&&bytes==sizeof(generated)&&generated.SubmitIrql==1&&generated.OperationStatus==0&&generated.BytesRead==4096,"generated paging read");
  Check(RevertToSelf()!=0,"revert before later query");
  SQ_EVENT event{};SQ_CONTEXT_REPLY legacy{};SQ_DEFERRED_TOKEN_CONTEXT evidence{};bool found=false;ULONGLONG deadline=GetTickCount64()+30000;
  while(GetTickCount64()<deadline){
   HRESULT hr=Send(port,SQ_GET_EVENT,0,0,&event,sizeof(event),&bytes);
   if(FAILED(hr)){Sleep(10);continue;}
   Check(bytes==sizeof(event)&&event.Version==4,"base protocol");
   if(event.Major==3&&event.CaptureIrql==1){
    Check(SUCCEEDED(Send(port,SQ_GET_THREAD_CONTEXT,event.Instance,event.Sequence,&legacy,sizeof(legacy),&bytes))&&bytes==sizeof(legacy)&&memcmp(&legacy.Event,&event,sizeof(event))==0,"legacy extension preserves operation bytes");
    Check(FAILED(Send(port,SQ_GET_DEFERRED_TOKEN_CONTEXT,event.Instance,event.Sequence+1,&evidence,sizeof(evidence),&bytes)),"mismatched linkage rejected");
    Check(FAILED(Send(port,SQ_GET_DEFERRED_TOKEN_CONTEXT,event.Instance,event.Sequence,&evidence,sizeof(evidence)-8,&bytes)),"short output rejected");
    Check(SUCCEEDED(Send(port,SQ_GET_DEFERRED_TOKEN_CONTEXT,event.Instance,event.Sequence,&evidence,sizeof(evidence),&bytes))&&bytes==sizeof(evidence),"deferred context");
    found=true;
   }
   Check(SUCCEEDED(Send(port,SQ_ACK_EVENT,event.Instance,event.Sequence,nullptr,0,&bytes)),"ACK");
   if(found)break;
  }
  if(!found){SQ_HEALTH health{};HRESULT hr=Send(port,SQ_GET_HEALTH,0,0,&health,sizeof(health),&bytes);fprintf(stderr,"APC timeout health hr=0x%08lX sequence=%lld names_failed=%lld dropped=%lld queued=%ld scope=%lu\n",(ULONG)hr,health.Sequence,health.NameFailures,health.Dropped,health.Queued,health.RootConfigured);}
  Check(found,"APC event timeout");
  Check(event.ProcessId==GetCurrentProcessId()&&event.ThreadId==GetCurrentThreadId()&&(ULONGLONG)event.ProcessCreatedUtc==birth&&event.Status==0&&evidence.Instance==event.Instance&&evidence.Sequence==event.Sequence&&evidence.Version==1&&evidence.Size==sizeof(evidence)&&evidence.ReferenceIrql==1&&evidence.ReferencedUtc>0&&evidence.QueriedUtc>0&&evidence.MetadataTiming==1&&(event.Flags&SQ_F_CONTEXT_IRQL)!=0&&event.ThreadEffective.Captured==0,"event identity and timing");
  LPSTR sid=nullptr;
  Check(evidence.ThreadOwnerPrimary.Captured==31&&evidence.RequestorPrimary.Captured==31&&(ULONGLONG)evidence.ThreadProcessCreatedUtc==birth&&evidence.Image[0]!=0&&evidence.CollectionStatus==0,"later primary and image metadata explicitly collected");
  LPSTR ownerSid=nullptr,requestorSid=nullptr;
  Check(ConvertSidToStringSidA((PSID)evidence.ThreadOwnerPrimary.Sid,&ownerSid)!=0&&strcmp(ownerSid,"S-1-5-18")==0,"later thread-owner SYSTEM SID");
  Check(ConvertSidToStringSidA((PSID)evidence.RequestorPrimary.Sid,&requestorSid)!=0&&strcmp(requestorSid,"S-1-5-18")==0,"later requestor SYSTEM SID");
  LocalFree(ownerSid);LocalFree(requestorSid);
  if(i<32){
   ULONGLONG tokenId=0,modifiedId=0,authenticationId=0;memcpy(&tokenId,&truth.TokenId,sizeof(tokenId));memcpy(&modifiedId,&truth.ModifiedId,sizeof(modifiedId));memcpy(&authenticationId,&truth.AuthenticationId,sizeof(authenticationId));
   Check(evidence.Impersonation==2&&evidence.ThreadEffective.Captured==31&&evidence.ThreadEffective.TokenId==tokenId&&evidence.ThreadEffective.ModifiedId==modifiedId&&evidence.ThreadEffective.AuthenticationId==authenticationId&&evidence.EntryImpersonationLevel==(ULONG)truth.ImpersonationLevel,"held effective token");
   Check(ConvertSidToStringSidA((PSID)evidence.ThreadEffective.Sid,&sid)!=0&&strcmp(sid,"S-1-5-19")==0,"effective SID");
  }else Check(evidence.Impersonation==1&&evidence.ThreadEffective.Captured==0&&evidence.EntryImpersonationLevel==0xffffffff,"no impersonation not fabricated");
  printf("{\"case\":\"integrated_deferred_token\",\"index\":%d,\"pid\":%llu,\"tid\":%llu,\"process_birth\":%llu,\"impersonating\":%lu,\"effective_sid\":%s%s%s,\"collection_status\":%ld,\"reference_irql\":%lu,\"base_stays_partial\":true,\"metadata_timing\":\"later_query_of_entry_referenced_token\"}\n",i,event.ProcessId,event.ThreadId,birth,evidence.Impersonation,sid?"\"":"",sid?sid:"null",sid?"\"":"",evidence.CollectionStatus,evidence.ReferenceIrql);
  if(sid)LocalFree(sid);
  wchar_t rawPath[MAX_PATH]{};Check(swprintf_s(rawPath,L"%s.raw-%d.bin",args[2],i)>0,"raw path");
  HANDLE raw=CreateFileW(rawPath,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);Check(raw!=INVALID_HANDLE_VALUE,"new native raw evidence");
  Check(WriteFile(raw,&legacy,sizeof(legacy),&bytes,nullptr)!=0&&bytes==sizeof(legacy),"raw operation evidence");
  Check(WriteFile(raw,&evidence,sizeof(evidence),&bytes,nullptr)!=0&&bytes==sizeof(evidence)&&FlushFileBuffers(raw)!=0,"raw deferred evidence");CloseHandle(raw);
 }
 Drain(port);CloseHandle(port);CloseHandle(sender);CloseHandle(file);CloseHandle(token);CloseHandle(primary);
 printf("{\"complete\":true,\"actual_read_cases\":33,\"filter_manager_apc_cases\":33,\"no_impersonation_control\":true,\"production_integrated\":false,\"full_callback_coverage\":false}\n");return 0;
}
