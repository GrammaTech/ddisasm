#include <stdio.h>

typedef struct
{
    int f1;
    int f2;
} A;

A array[10];

int main()
{
    int i;

    for(i = 0; i < 10; ++i)
    {
        array[i].f1 = i;
    }
    array[0].f2 = 10;
    for(i = 1; i < 10; ++i)
    {
        array[i].f2 = i + 10;
    }

    return 0;
}
