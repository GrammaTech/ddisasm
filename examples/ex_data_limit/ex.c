#include <stdio.h>

#include "fun.h"

void foo(const char* str)
{
    printf("foo: %s\n", str);
}

const char* g_str = "Hello World!";

A g = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &foo, 0, &g_str, 0, 0, 0, 0, 0};

// The external function 'fun' has explicit references to 'foo' or 'g_str'.
// However, this program itself does not have any.
// In non-pie version of this program, this may make those symbols in data,
// tricky to symbolize.
// A solution is to add a 'data_limit' at the address with non-zero value
// after consecutive zeros.
int main()
{
    int i = 0;
    while(g.arr[i++] == 0)
    {
        printf("%d\n", i);
    }

    fun(&g);

    return 0;
}
