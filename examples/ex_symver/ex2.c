#include <stdio.h>
#include <stdlib.h>

#include "foo.h"

__asm__(".symver foo,foo@LIBFOO_2.0");

int main()
{
    foo();
    return 0;
}
