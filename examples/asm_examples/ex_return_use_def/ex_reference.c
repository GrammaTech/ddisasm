/**
Original source included for reference.

The key properties of this example which make it difficult to correctly generate def_used are:

* A register is defined in a function, returned, and used by the caller
* The function uses the register in a separate basic block between defining and returning the
  register.
*/

#include <stdio.h>
#include <string.h>

int count = 0;

char *hello = "-Hello World";
char *goodbye = "-Goodbye World";

static char *get_ptr(void)
{
    char *ptr = hello;

    // Add some control flow
    if(count > 0)
    {
        ptr = goodbye;
    }

    if(ptr[0] != ' ')
    {
        ptr[0] = ' ';
    }

    count++;
    return ptr;
}

int main(void)
{
    for(int i = 0; i < 2; i++)
    {
        char *ptr = get_ptr();
        if(!ptr)
            continue;

        puts(ptr);
    }

    return 0;
}
