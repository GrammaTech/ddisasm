#include <stdio.h>
#include <stdlib.h>

// This example is to make sure ddisasm to handle various relocations
// that remain with `--emit-relocs`.

extern int curbuf[];
extern void bar(int a);

void fun(int a, int b)
{
    curbuf[0] = a + b;
}

int main()
{
    fun(10, 20);
    bar(30);
    printf("%d, %d\n", curbuf[0], curbuf[1]);
    return 0;
}
