#include <stdio.h>
#include <windows.h>

BOOL ReadPtr(const DWORD* p)
{
    BOOL bBad = 0;
    __try
    {
        DWORD dwDummy = *p;
        printf("%X\n", dwDummy);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        puts("exception");
        bBad = 1;
    }
    return (bBad);
}

int main()
{
    int valid = 0xBEEF;
    if(ReadPtr(&valid))
    {
        puts("ERROR");
    }
    if(ReadPtr(0))
    {
        puts("OK");
    }
    return EXIT_SUCCESS;
}
