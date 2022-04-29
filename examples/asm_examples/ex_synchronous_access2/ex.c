/*
The C version of the program is included only for reference.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct combined
{
    int16_t num;
    char ch;
    char ch2;
} combined;

combined struc_array[10] = {{0, 'a', 'b'},      {0, 'a', 'b'},      {0, 'a', 'b'},
                            {0, 'a', 'b'},      {0x4142, 'a', 'b'}, {0x4142, 'a', 'b'},
                            {0x4142, 'a', 'b'}, {0x4142, 'a', 'b'}, {0x4142, 'a', 'b'},
                            {0, 'a', 'b'}};

int main()
{
    puts("Printing data");

    for(int i = 0; i < 10; ++i)
        printf("%i %c %c \n", struc_array[i].num, struc_array[i].ch, struc_array[i].ch2);

    return 0;
}
