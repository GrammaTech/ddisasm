#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static char buffer[10];

void print()
{
    for(int i = 0; i < 9; ++i)
        buffer[i] = 0x30 + i;
    buffer[9] = 0;
    printf("%s\n", buffer);
}
