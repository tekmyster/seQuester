#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../../src/seQuester.WindowsKernel/ExecutableAccess.h"
typedef struct { ACCESS_MASK Requested; BOOLEAN Candidate, Qualified; } CASE;
void mainCRTStartup(void)
{
    GENERIC_MAPPING mapping={FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
    CASE cases[]={
        {GENERIC_READ|GENERIC_EXECUTE,TRUE,TRUE},
        {GENERIC_ALL,TRUE,TRUE},
        {GENERIC_EXECUTE,TRUE,FALSE},
        {GENERIC_READ,FALSE,FALSE},
        {GENERIC_WRITE,FALSE,FALSE},
        {FILE_READ_DATA|FILE_EXECUTE,TRUE,TRUE},
        {FILE_EXECUTE|SYNCHRONIZE,TRUE,FALSE},
        {FILE_READ_ATTRIBUTES|FILE_EXECUTE,TRUE,FALSE},
        {MAXIMUM_ALLOWED|GENERIC_READ|GENERIC_EXECUTE,TRUE,FALSE},
        {MAXIMUM_ALLOWED,FALSE,FALSE},
        {0,FALSE,FALSE}
    };
    unsigned i;
    for(i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        ACCESS_MASK mapped=cases[i].Requested;
        if(SqExecutableCandidateAccess(mapped)!=cases[i].Candidate)ExitProcess(10+i);
        MapGenericMask(&mapped,&mapping);
        if(SqExecutableMappedAccess(mapped)!=cases[i].Qualified)ExitProcess(40+i);
    }
    // Unmapped GENERIC flags must never accidentally pass the data-read gate.
    if(SqExecutableMappedAccess(GENERIC_ALL|FILE_READ_DATA|FILE_EXECUTE))ExitProcess(80);
    ExitProcess(0);
}
