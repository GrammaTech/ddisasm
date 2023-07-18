#include <stdio.h>
#include <stdlib.h>

static void setup(void) __attribute__((constructor));

int i = 0;

void setup(void)
{
    i = 100;
}

int main()
{
    printf("My number is: %d\n", i);
    return 0;
}
