#include "test.h"
#include <stdio.h>

__declspec(dllexport) void message()
{
    puts("hello dll");
}
