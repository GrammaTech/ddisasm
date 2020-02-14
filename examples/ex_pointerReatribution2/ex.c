#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

int counters[2] = {0};

void print()
{
    for(int i = 0; i < 2; ++i)
        printf("%i\n", counters[i]);
}

int main()
{
    int input;
    input = getchar();
    switch(input)
    {
        case 'A':
            puts("option A");
            break;
        case 'B':
            puts("option B");
            break;
        default:
            puts("Unknown option.");
            return 0;
    }
    counters[input - 'A']++;
    print();
}
