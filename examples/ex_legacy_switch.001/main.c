// Originally adapted from http://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=100473
// The code has been rewritten so recompilation is more likely to result in the
// double table lookup for a control-flow transfer.

#include <stdio.h>

void f1(unsigned int i)
{
    char c = 'A' + i;
    if (c == 'B') printf("double-table-lookup-%c-1\n", c);
    if (c == 'C') printf("double-table-lookup-%c-1\n", c);
    if (c == 'F') printf("double-table-lookup-%c-1\n", c);
}

void f2(unsigned int i)
{
    char c = 'A' + i;
    if (c == 'E') printf("double-table-lookup-%c-2\n", c);
    if (c == 'G') printf("double-table-lookup-%c-2\n", c);
    if (c == 'H') printf("double-table-lookup-%c-2\n", c);
}

void f3(unsigned int i) { printf("double-table-lookup-default\n"); }

int main(int argc, char *argv[]) {
    unsigned int i = 0;

    if (argc != 2) {
        return 1;
    }

    typedef void (*FN)(unsigned int);

    // bottom layer of disptach
    static FN tgts[3] = { f3, f1, f2 };

    // top layer of disptach, used to index tgts
    static int idxs[32] = { 0, 1, 1, 0, 2, 1, 2, 2 };

    i = (argv[1][0] - 'A');

    // simulates a nested table switch
    if (i < 8) tgts[idxs[i]](i);

    return 0;
}
