#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

uint64_t state[16] = {0};

void sprng(uint64_t seed)
{
    uint64_t state_64 = seed;
    for(int i = 0; i < 16; i++)
    {
        state_64 ^= state_64 >> 27;
        state_64 ^= state_64 >> 13;
        state_64 ^= state_64 >> 46;
        state[i] = state_64 * 1865811235122147685;
    }
}

int main()
{
    sprng(89876986765987652);
    int a = 0;
    int b = 4;
    a = b + 3;
    printf("%i \n", a);
    for(int i = 0; i < 16; i++)
        printf("%" PRIu64 " \n", state[i]);
    return 0;
}
