#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
int main(int argc,char** argv){
 if(argc!=3)return 2;
 HANDLE process=GetCurrentProcess();
 SymSetOptions(SYMOPT_UNDNAME|SYMOPT_DEFERRED_LOADS|SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_NO_PROMPTS|SYMOPT_EXACT_SYMBOLS);
 if(!SymInitialize(process,argv[2],FALSE)){fprintf(stderr,"SymInitialize failed %lu\n",GetLastError());return 1;}
 DWORD64 base=SymLoadModuleEx(process,nullptr,argv[1],"sqnt",0x180000000,0,nullptr,0);
 if(!base){fprintf(stderr,"SymLoadModuleEx failed %lu\n",GetLastError());SymCleanup(process);return 1;}
 bool all=true;
 for(const char* name:{"KiInitDynamicTraceSupport","KeSetSystemServiceCallback","KiSystemServiceUser","KiSystemServiceRepeat","KiDynamicTraceContext","KiDynamicTraceCallouts"}){
  std::vector<unsigned char> storage(sizeof(SYMBOL_INFO)+MAX_SYM_NAME);auto symbol=reinterpret_cast<SYMBOL_INFO*>(storage.data());
  symbol->SizeOfStruct=sizeof(SYMBOL_INFO);symbol->MaxNameLen=MAX_SYM_NAME;
  std::string qualified=std::string("sqnt!")+name;
  if(!SymFromName(process,qualified.c_str(),symbol)){printf("{\"Symbol\":\"%s\",\"Available\":false,\"Win32Error\":%lu}\n",name,GetLastError());all=false;continue;}
  printf("{\"Symbol\":\"%s\",\"Available\":true,\"Rva\":%llu,\"Size\":%lu,\"TypeIndex\":%lu}\n",name,symbol->Address-base,symbol->Size,symbol->TypeIndex);
 }
 IMAGEHLP_MODULE64 info{};info.SizeOfStruct=sizeof(info);
 if(!SymGetModuleInfo64(process,base,&info)||info.SymType!=SymPdb||info.PdbUnmatched){fprintf(stderr,"Exact matching PDB not established\n");SymCleanup(process);return 1;}
 printf("{\"ExactPdb\":true,\"PdbAge\":%lu,\"PdbGuid\":\"%08lX-%04X-%04X-",info.PdbAge,info.PdbSig70.Data1,info.PdbSig70.Data2,info.PdbSig70.Data3);
 for(auto b:info.PdbSig70.Data4)printf("%02X",b);
 printf("\",\"AllSymbolsAvailable\":%s,\"RuntimeQualified\":false}\n",all?"true":"false");SymCleanup(process);return 0;
}
