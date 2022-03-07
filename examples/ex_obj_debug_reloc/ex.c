/**
This example is used to verify that debug relocations are not erroneously
applied to other sections.

This bug was occurring in .o files

See issue #323.
*/

#include <stdint.h>
#include <stdio.h>

struct stru
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
};

/**
Copy some fields around in a struct.

These struct operations generate loads of memory access instructions that may
be symbolized. We want some instructions that may be symbolized to collide with
some debug relocations.
*/
void flip_stru(struct stru *stru1, struct stru *stru2)
{
    stru2->a = stru1->d;
    stru2->b = stru1->c;
    stru2->c = stru1->b;
    stru2->d = stru1->a;
}

int main(void)
{
    printf("hello world\n");

    struct stru stru1 = {.a = 1, .b = 2, .c = 3, .d = 4};
    struct stru stru2;
    flip_stru(&stru1, &stru2);

    printf("%d %d %d %d\n", stru2.a, stru2.b, stru2.c, stru2.d);
    return 0;
}
