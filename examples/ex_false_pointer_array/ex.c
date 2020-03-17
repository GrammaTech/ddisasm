#include <stdio.h>
#include <stdlib.h>

// the array should no be classified as a pointer even though it has a value
// that coincides with the code section.

void f()
{
    puts("f");
}
void g()
{
    puts("g");
}

char array[8] = {0x99, 0x05, 0x40, 0, 0, 0, 0, 0};
void (*f_pointer)() = &f;
void (*g_pointer)() = &g;

void print()
{
    for(int i = 0; i < 7; ++i)
        printf("%i\n", array[i]);
}

int main()
{
    (*f_pointer)();
    (*g_pointer)();
    puts("Printing data");
    print();
    return 0;
}
