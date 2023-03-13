#include <stdio.h>

static __thread int index;
static __thread char buffer[16];
__thread char buffer_lib[16];
void fun()
{
    buffer[index % 16] = '.';
    buffer_lib[index % 16] = '.';
    index++;
    printf("%d ", index);
    printf("%s ", buffer);
    printf("%s\n", buffer_lib);
}
