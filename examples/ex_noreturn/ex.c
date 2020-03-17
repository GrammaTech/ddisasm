#include <stdio.h>
#include <stdlib.h>

void fun(int a, int b)
{
    int i = 0;
    while(a < b)
    {
        ++i;
        ++a;
    }
}
int main()
{
    fun(10, 20);
    puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
    exit(0);
}
