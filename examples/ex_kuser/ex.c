#include <stdio.h>
#include <windows.h>

#define KUSER_SHARED_DATA 0x7ffe0000
#define MAJOR_VERSION_OFFSET 0x026C
#define MINOR_VERSION_OFFSET 0x0270

int main(int argc, char *argv[])
{
    ULONG major = *(PULONG)(KUSER_SHARED_DATA + MAJOR_VERSION_OFFSET);
    ULONG minor = *(PULONG)(KUSER_SHARED_DATA + MINOR_VERSION_OFFSET);
    printf("%lu.%lu\n", major, minor);
}
