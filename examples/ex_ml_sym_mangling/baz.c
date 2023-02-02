#include <stdio.h>

#include "foo.h"

__declspec(dllexport) void Baz()
{
    Foo();
    _Bar();
    puts("Baz");
}
__declspec(dllexport) void _Baz()
{
    Foo();
    _Bar();
    puts("_Baz");
}
__declspec(dllexport) void __Baz()
{
    Foo();
    _Bar();
    puts("__Baz");
}
