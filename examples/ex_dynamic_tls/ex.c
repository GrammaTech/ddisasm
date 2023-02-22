#include <stdio.h>
#include <stdlib.h>

#include "fun.h"

int main()
{
    fun();
    fun_static();
    fun();
    fun_static();
    fun();
    fun_static();
    return 0;
}
