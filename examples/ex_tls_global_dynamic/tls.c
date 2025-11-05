#include <stdio.h>

extern __thread int initialized1;

extern __thread int uninitialized1;

extern __thread long initialized2;

extern __thread int uninitialized2;

int foo()
{
    initialized1++;
    printf("%d\n", initialized1);
    uninitialized1++;
    printf("%d\n", uninitialized1);
    initialized2++;
    printf("%ld\n", initialized2);
    uninitialized2++;
    printf("%d\n", uninitialized2);

    return initialized1 + uninitialized1 + initialized2 + uninitialized2;
}
