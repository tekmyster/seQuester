#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static unsigned ReadCalls,WriteCalls,SetCalls,InvalidArguments;
extern "C" unsigned long long SqAbiExercise(unsigned operation);
static LONG ReadWrite(unsigned long long a,unsigned long long b,unsigned long long c,
    unsigned long long d,unsigned long long e,unsigned long long f,unsigned g,
    unsigned long long h,unsigned long long i)
{
    if(a!=1||b!=2||c!=3||d!=4||e!=5||f!=6||g!=7||h!=8||i!=9)InvalidArguments++;
    return static_cast<LONG>(0xC0000022U);
}
extern "C" LONG SqReadBody(unsigned long long a,unsigned long long b,unsigned long long c,
    unsigned long long d,unsigned long long e,unsigned long long f,unsigned g,
    unsigned long long h,unsigned long long i)
{ReadCalls++;return ReadWrite(a,b,c,d,e,f,g,h,i);}
extern "C" LONG SqWriteBody(unsigned long long a,unsigned long long b,unsigned long long c,
    unsigned long long d,unsigned long long e,unsigned long long f,unsigned g,
    unsigned long long h,unsigned long long i)
{WriteCalls++;return ReadWrite(a,b,c,d,e,f,g,h,i);}
extern "C" LONG SqSetBody(unsigned long long a,unsigned long long b,unsigned long long c,
    unsigned d,unsigned e)
{SetCalls++;if(a!=1||b!=2||c!=3||d!=4||e!=5)InvalidArguments++;return static_cast<LONG>(0xC0000022U);}
int main()
{
    unsigned failures=0;
    for(unsigned n=0;n<1000;n++)for(unsigned op=1;op<=3;op++)if(SqAbiExercise(op)!=0)failures++;
    bool pass=failures==0&&InvalidArguments==0&&ReadCalls==1000&&WriteCalls==1000&&SetCalls==1000;
    printf("{\"Passed\":%s,\"ReadCases\":%u,\"WriteCases\":%u,\"SetInformationCases\":%u,"
        "\"InvalidArguments\":%u,\"StatusOrNonvolatileFailures\":%u,"
        "\"VmExitQualified\":false,\"FilesystemCaptureQualified\":false}\n",
        pass?"true":"false",ReadCalls,WriteCalls,SetCalls,InvalidArguments,failures);
    return pass?0:1;
}
