#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int add(int a, int b)
{
    return (a + b);
}

void main(void)
{
    int sum;
    int i;

    sum = 0;
    i = 1;
    while(i < 0xb)
    {
        sum = add(sum, i);
        i = add(i, 1);
        printf("sum = %d\n", sum);
        printf("i = %d\n", i);
    }
    return;
}
