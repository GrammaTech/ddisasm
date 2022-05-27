/*
The C version of the program is included only for reference.

'array' is accessed with size 2 and 4. Only
the access with size 2 has a non-zero multiplier, the access with size 4
is a one time access.

Right after 'array' there is a function pointer 'msg_pointer' that is
not accessed directly. If the size 4 is erroneously considered
with the non-zero multiplier, the last propagated access will conflict
with the function pointer and lead to an error in symbolization.

*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void msg()
{
    puts("function reached through pointer");
}

int16_t array[8] = {1, 2, 3, 4, 5, 6, 7, 8};
void (*msg_pointer)() = &msg;

int main()
{
    puts("Printing data");

    for(int i = 0; i < 8; ++i)
        printf("%i  \n", array[i]);

    // access array[0] with a different size
    printf("%i  \n", *((int*)array));

    // avoid accessing msg_pointer directly
    void (**msg_computed_pointer)() = (void (**)())array;
    // two pointers of 8 bytes= 16 bytes = 8 int16 elems
    // don't do this at home
    msg_computed_pointer += 2;
    (**msg_computed_pointer)();

    return 0;
}
