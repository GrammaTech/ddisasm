#include <stdio.h>

#include "test.h"

int bar(int n)
{
    printf("bar: %d\n", n);
    return n + 20;
}
