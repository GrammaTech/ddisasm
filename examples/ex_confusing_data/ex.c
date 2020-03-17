#include <stdio.h>
#include <stdlib.h>

int16_t array[12] = {10, 11, 12, 1443, 64, 0, 0, 0, // 00 00 00 00 00 40 05 A1 the address of main
                     17, 18, 19, 20};

void print()
{
    for(int i = 0; i < 11; ++i)
        printf("%i\n", array[i]);
}

int main()
{
    puts("Printing data");
    print();
    return 0;
}
