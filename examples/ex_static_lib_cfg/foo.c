#include <stdio.h>

#include "test.h"

int foo(int n)
{
    printf("foo: %d\n", n);
    return bar(n);
}
