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
            case 5:
                one(a);
                break;
            case 6:
                two(a);
                break;
            case 7:
                three(a);
                break;
            case 8:
                four(a);
                break;
            default:
                def(a);
        }
        ++a;
    }
}

void fun_wide(int a, int b)
{
    while(a < b)
    {
        switch(a)
        {
            case 1:
                one(a);
                two(a);
                three(a);
                four(a);
                one(a);
                two(a);
                three(a);
                four(a);
                break;
            case 2:
                one(a);
                two(a);
                three(a);
                four(b);
                one(a);
                two(a);
                three(a);
                four(b);
                break;
            case 3:
                one(a + 2);
                two(a + 2);
                three(b + 2);
                four(a + 2);
                one(a + 2);
                two(a + 2);
                three(b + 2);
                four(a + 2);
                break;
            case 4:
                one(a);
                two(b);
                three(a);
                four(a);
                one(a);
                two(b);
                three(a);
                four(a);
                break;
            case 5:
                one(a);
                two(b);
                three(a);
                four(a);
                one(a);
                two(b);
                three(a);
                four(a);
                break;
            case 6:
                one(b);
                two(a);
                three(a);
                four(a);
                break;
            case 7:
                one(a);
                two(a);
                three(b);
                four(b);
                one(a);
                two(a);
                three(b);
                four(b);
                break;
            case 8:
                one(b);
                two(b);
                three(a);
                four(a);
                one(b);
                two(b);
                three(a);
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
    fun(1, 6);
    fun_wide(1, 6);
    return 0;
}
