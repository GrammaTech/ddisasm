#include <stdio.h>

int main()
{
    fprintf(stderr, "%s %s %s\n", "a", " string", " in stderr");
    fprintf(stdout, "%s %s %s\n", "a", " string", " in stdout");
    return 0;
}
