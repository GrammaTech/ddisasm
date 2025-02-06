#include <stdio.h>

// This example is to check if ddisasm chooses right symbols for GOT entries.
// data.c defines a global array `my_strings` (GLOBAL), which this function
// `fun` refers to.
// Also, bar.c defines a static array with the same name (LOCAL).
//
// Symbols with same name are disambiguated: the global symbol keeps the
// original name, and the other local symbol(s) are suffixed with _disamb_.
//
// Ddisasm should choose GLOBAL symbols over disambiguated local symbols
// for GOT entries.

extern const char* my_strings[];

void fun()
{
    int i = 0;
    for(i = 0; i < 3; i++)
    {
        printf("fun: %d: %s\n", i, my_strings[i]);
    }
}
