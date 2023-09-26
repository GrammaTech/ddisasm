
#include <stdio.h>
extern void foo_fun();
extern void bar_fun();

int main()
{
    puts("calling foo_fun");
    foo_fun();
    puts("now bar_fun");
    bar_fun();
    return 0;
}
