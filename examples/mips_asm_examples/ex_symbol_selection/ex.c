#include <stdio.h>
#include <stdlib.h>

extern void fun();
extern void bar();

int main()
{
    bar();
    fun();
    puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
    return 0;
}
