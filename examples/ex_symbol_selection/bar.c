#include <stdio.h>

static const char* my_strings[] = {"hello four", "hello five", "hello six"};

void bar()
{
    int i = 0;
    for(; i < 3; i++)
    {
        printf("bar: %d: %s\n", i, my_strings[i]);
    }
}
