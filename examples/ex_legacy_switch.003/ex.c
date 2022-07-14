// Adapted from http://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=100473
// switch3.cpp
//
// According to the article, a switch can sometimes be compiled as a "binary
// search". Rather than trying to get the compiler to do this, we'll just put
// in the binary search ... for completeness.

#include <stdio.h>

int main(int argc, char *argv[])
{
    int i = 0;

    if(argc == 2 && argv[1][0] != '\0' && argv[1][1] != '\0' && argv[1][2] != '\0')
    {
        // Note, this is not guaranteed to use digits, but it doesn't matter
        i = (argv[1][0] - '0') * 100 + (argv[1][1] - '0') * 10 + (argv[1][2] - '0');

        if(i > 700)
        {
            if(i == 750)
                puts("bin-search-A");
            else if(i == 800)
                puts("bin-search-B");
            else if(i == 900)
                puts("bin-search-C");
            else
                goto DEFAULT;
        }
        else if(i == 700)
        {
            puts("bin-search-D");
        }
        else if(i > 250)
        {
            if(i == 500)
                puts("bin-search-E");
            else
                goto DEFAULT;
        }
        else if(i == 250)
        {
            puts("bin-search-F");
        }
        else if(i == 100)
        {
            puts("bin-search-G");
        }
        else if(i == 200)
        {
            puts("bin-search-H");
        }

        return 0;

    DEFAULT:
        puts("bin-search-default");

        return 0;
    }

    return 1;
}
