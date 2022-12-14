#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int foo();

int main()
{
    extern char **environ;
    int i = 0;
    while(environ[i])
    {
        if(strlen(environ[i]) > 4)
        {
            if(strncmp(environ[i], "HOME", 4) == 0)
            {
                printf("%s\n", environ[i++]);
            }
        }
        i++;
    }
    foo();
    return 0;
}
