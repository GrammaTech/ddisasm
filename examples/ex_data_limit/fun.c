#include "fun.h"

#include <stdio.h>

void fun(A* a)
{
    (*a->fun_ptr)(*a->str);
}
