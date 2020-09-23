#include <stdio.h>

// Initialized thread-local object (.tdata):
__thread int i = 4;

// Uninitialized thread-local object (.tbss):
__thread int j;

__thread long k = 10;

__thread int l;

int main()
{
    i++;
    printf("%d\n", i);
    j++;
    printf("%d\n", j);
    k++;
    printf("%ld\n", k);
    l++;
    printf("%d\n", l);
}
