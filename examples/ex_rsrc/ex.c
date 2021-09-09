#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "resource.h"

int main()
{
    HRSRC hResource = FindResourceA(NULL, MAKEINTRESOURCEA(RCDATA1), MAKEINTRESOURCEA(RT_RCDATA));
    if(!hResource)
    {
        puts("ERROR: FindResource: RCDATA1");
        return EXIT_FAILURE;
    }

    HGLOBAL hMemory = LoadResource(NULL, hResource);
    if(!hMemory)
    {
        puts("ERROR: LoadResource: RCDATA1");
        return EXIT_FAILURE;
    }

    size_t size = SizeofResource(NULL, hResource);
    void* ptr = LockResource(hMemory);

    fprintf(stderr, "%zu @ %p\n", size, ptr);
    fprintf(stderr, "%s\n", (char*)ptr);

    puts("OK");
    return EXIT_SUCCESS;
}
