#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int c;

    while(1)
    {
        static struct option long_options[] = {
            {"verbose", no_argument, 0, 'v'}, {"add", no_argument, 0, 'a'}, {0, 0, 0, 0}};
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "av", long_options, &option_index);

        /* Detect the end of the options. */
        if(c == -1)
            break;

        switch(c)
        {
            case 'v':
                puts("option -v\n");
                break;
            case 'a':
                puts("option -a\n");
                break;
            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
        }
    }
    return 0;
}
