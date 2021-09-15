#include <stdio.h>

static __thread int index;
static __thread char buffer[16];

void fun(int a, int b)
{
    buffer[index % 16] = '.';
    index++;
    printf("%d ", index);
    printf("%s\n", buffer);
}
