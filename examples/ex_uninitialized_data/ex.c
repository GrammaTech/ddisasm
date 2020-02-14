#include <stdio.h>
#include <stdlib.h>

int array[1000];

void init()
{
    for(int i = 0; i < 10; ++i)
        array[i] = i;
}

void print()
{
    for(int i = 0; i < 10; ++i)
        printf("%i\n", array[i]);
}

int main()
{
    puts("Storing data");
    init();
    puts("Printing data");
    print();
    return 0;
}
