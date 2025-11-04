#include <stdio.h>

extern __thread int i;

extern __thread int j;

extern __thread long k;

extern __thread int l;

int foo()
{
    i++;
    printf("%d\n", i);
    j++;
    printf("%d\n", j);
    k++;
    printf("%ld\n", k);
    l++;
    printf("%d\n", l);

    return i + j + k + l;
}
