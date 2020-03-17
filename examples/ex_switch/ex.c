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
int def(int a)
{
    puts("last");
    return a;
}

void fun(int a, int b)
{
    while(a < b)
    {
        switch(a)
        {
            case 1:
                one(a);
                break;
            case 2:
                two(a);
                break;
            case 3:
                three(a);
                break;
            case 4:
                four(a);
                break;
            default:
                def(a);
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
