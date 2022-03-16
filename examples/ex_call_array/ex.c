#include <stdio.h>
#include <stdlib.h>

int one(int a)
{
    puts("one");
    return a;
}
int two(int a)
{
    puts("two");
    return a;
}
int three(int a)
{
    puts("three");
    return a + 1;
}
int four(int a)
{
    puts("four");
    return a;
}

int (*funcs[])(int a) = {one, two, three, four};

void fun(int a, int b)
{
    while(a < b)
    {
        if(a <= sizeof(funcs) / sizeof(funcs[0]))
        {
            (*funcs[a - 1])(b);
        }
        ++a;
    }
}
int main()
{
    puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
    fun(1, 6);
    return 0;
}
