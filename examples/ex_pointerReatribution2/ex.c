#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int
counters[2] = {0};
int
main()
{
    int  input;
    input = getchar();
    switch  (input - 'A')
    {
    case  0:
        puts("option A");
        break;
    case  1:
        puts("option B");
        break;
    case  2:
        puts("option C");
        break;
    case  3:
        puts("option D");
        break;
    case  4:
        puts("option E");
        break;
    case  5:
        puts("option F");
        break;
    case  6:
        puts("option G");
        break;
    case  7:
        puts("option H");
        break;
    case  8:
        puts("option I");
        break;
        
    default:
        puts("Unknown option.");
        return 0;
    }
    counters[input - 'A'] ++;
}
