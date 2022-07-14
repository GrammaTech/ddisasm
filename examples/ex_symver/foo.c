#include <stdio.h>

__asm__(".symver bar,bar@@LIBFOO_2.0");
int bar = 42;

__asm__(".symver foo1,foo@LIBFOO_1.0");
void foo1(void)
{
    puts("foo 1.0");
}

__asm__(".symver foo2,foo@@LIBFOO_2.0");
void foo2(void)
{
    puts("foo 2.0");
}
