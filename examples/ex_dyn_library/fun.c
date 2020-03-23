#include <stdio.h>

void fun(int a, int b)
{
    int i = 0;
    while(a < b)
    {
        ++i;
        ++a;
        printf("%i\n", i);
    }
}
