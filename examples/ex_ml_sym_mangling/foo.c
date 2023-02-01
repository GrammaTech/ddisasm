#include "foo.h"

#include <stdio.h>

__declspec(dllexport) void Foo()
{
    puts("Foo");
}

__declspec(dllexport) void _Bar()
{
    puts("_Bar");
}
