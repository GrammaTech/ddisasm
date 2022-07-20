

#include <stdio.h>

__asm__(".symver bar1,bar@LIBBAR_1.0");
void bar1()
{
    puts("bar 1");
}

__asm__(".symver bar2,bar@@LIBBAR_2.0");
void bar2()
{
    puts("bar 2");
}
