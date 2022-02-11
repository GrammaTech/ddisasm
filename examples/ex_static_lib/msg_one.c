#include "libmsg.h"

char *get_msg_one(void)
{
    return "one";
}

// Having a second function implemented here (with a second string) ensures
// there is a string in the .rodata section that is *not* at the section start.
char *get_msg_five(void)
{
    return "five";
}
