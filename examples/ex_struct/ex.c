#include <stdio.h>
#include <stdlib.h>

typedef unsigned short ush;
typedef struct ct_data
{
    union {
        ush freq; /* frequency count */
        ush code; /* bit string */
    } fc;
    union {
        ush dad; /* father node in Huffman tree */
        ush len; /* length of bit string */
    } dl;
} ct_data;

#define Freq fc.freq
#define Code fc.code
#define Dad dl.dad
#define Len dl.len

#define D_CODES 30

static ct_data dyn_dtree[2 * D_CODES + 1]; /* distance tree */

static void init_block1()
{
    int n;
    for(n = 0; n < D_CODES; n++)
    {
        //      printf("dtree %i\n",n);
        dyn_dtree[n].Freq = 0;
    }
}
static void init_block2()
{
    int n;
    for(n = 0; n < D_CODES; n++)
    {
        printf("dtree %i\n", n);
        dyn_dtree[n].Freq = 0;
    }
}

int main()
{
    puts("init block 1");
    init_block1();
    puts("init block 2");
    init_block2();
    int n;
    for(n = 0; n < D_CODES; n++)
    {
        printf("content %i\n", dyn_dtree[n].Freq);
    }
    return 0;
}
