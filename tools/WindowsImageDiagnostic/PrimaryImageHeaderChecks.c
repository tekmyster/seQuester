#include <windows.h>
#include "../../src/RansomFree.WindowsKernel/PrimaryImageHeader.h"
static unsigned int checks;
static void Check(int ok){checks++;if(!ok)ExitProcess(checks);}
static int Kind(const WCHAR* name)
{
    WCHAR path[MAX_PATH];HANDLE file;LARGE_INTEGER size,position;DWORD read;unsigned char dos[64],pe[24];unsigned int offset;int result=0;
    if(!GetSystemDirectoryW(path,MAX_PATH)||lstrlenW(path)>MAX_PATH-32)ExitProcess(200);
    lstrcatW(path,L"\\");lstrcatW(path,name);file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE)ExitProcess(201);
    if(GetFileSizeEx(file,&size)&&ReadFile(file,dos,sizeof(dos),&read,NULL)&&SqPeOffset(dos,read,(unsigned long long)size.QuadPart,&offset)){
        position.QuadPart=offset;if(SetFilePointerEx(file,position,NULL,FILE_BEGIN)&&ReadFile(file,pe,sizeof(pe),&read,NULL))result=SqPeKind(pe,read);
    }
    CloseHandle(file);return result;
}
void mainCRTStartup(void)
{
    static unsigned char dos[64],pe[24];unsigned int offset=0;DWORD written;
    const char message[]="PASS 16 bounded primary-image header checks, including native cmd.exe and kernel32.dll\r\n";
    dos[0]='M';dos[1]='Z';dos[60]=64;pe[0]='P';pe[1]='E';pe[22]=2;
    Check(SqPeOffset(dos,64,88,&offset)&&offset==64);Check(SqPeKind(pe,24)==1);
    Check(!SqPeOffset(dos,63,88,&offset));Check(!SqPeOffset(dos,64,87,&offset));Check(!SqPeKind(pe,23));
    dos[60]=63;Check(!SqPeOffset(dos,64,88,&offset));dos[60]=64;
    dos[63]=0x80;Check(!SqPeOffset(dos,64,8388608,&offset));dos[63]=0;
    dos[0]='N';Check(!SqPeOffset(dos,64,88,&offset));dos[0]='M';
    pe[23]=0x20;Check(SqPeKind(pe,24)==2);pe[23]=0;pe[22]=0;Check(!SqPeKind(pe,24));pe[22]=2;
    pe[2]=1;Check(!SqPeKind(pe,24));pe[2]=0;
    Check(!SqPeOffset(NULL,64,88,&offset));Check(!SqPeOffset(dos,64,88,NULL));Check(!SqPeKind(NULL,24));
    Check(Kind(L"cmd.exe")==1);Check(Kind(L"kernel32.dll")==2);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),message,sizeof(message)-1,&written,NULL);ExitProcess(0);
}
