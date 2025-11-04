#include <stdio.h>

// Initialized thread-local object (.tdata):
__thread int initialized1 = 4;

// Uninitialized thread-local object (.tbss):
__thread int uninitialized1;

__thread long initialized2 = 10;

__thread int uninitialized2;

int main()
{
    initialized1++;
    printf("%d\n", initialized1);
    uninitialized1++;
    printf("%d\n", uninitialized1);
    initialized2++;
    printf("%ld\n", initialized2);
    uninitialized2++;
    printf("%d\n", uninitialized2);
}
