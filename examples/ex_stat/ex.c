#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct stat istat; /* status for input file */

int name_too_long(char *name, struct stat *statb)
{
    int s = strlen(name);
    printf("strlen done %i\n", s);

    char c = name[s - 1];
    struct stat tstat; /* stat for truncated name */
    int res;

    name[s - 1] = 'a';

    puts("before lstat");
    res = lstat(name, &tstat) == 0;
    puts("before same file");
    name[s - 1] = c;
    if(res)
    {
        puts("checking same file");
        return statb->st_ino == tstat.st_ino && statb->st_dev == tstat.st_dev;
    }
    return res;
}

int main()
{
    char *name = malloc(5);
    strcpy(name, "ex.c");
    lstat(name, &istat);
    fprintf(stdout, "File %s has %i \n", "ex.c", istat.st_mode);
    printf("%i \n", name_too_long(name, &istat));
    return 0;
}
