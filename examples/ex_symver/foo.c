#include <stdio.h>

__asm__(".symver bar,bar@LIBBAR_1.0");
__asm__(".symver bar2,bar@LIBBAR_2.0");

void bar();
void bar2();

__asm__(".symver foo1,foo@LIBFOO_1.0");
void foo1()
{
    puts("foo 1.0");
    bar();
}

__asm__(".symver foo2,foo@LIBFOO_2.0");

void foo2()
{
    puts("foo 2.0");
    bar2();
}

__asm__(".symver foo3,foo@@LIBFOO_3.0");
void foo3()
{
    puts("foo 3.0");
    bar2();
}
