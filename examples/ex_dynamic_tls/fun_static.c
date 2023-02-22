#include <stdio.h>

__attribute((tls_model("initial-exec"))) static __thread int index;
__attribute((tls_model("initial-exec"))) static __thread char buffer_initial_exec[16];

void fun_static()
{
    buffer_initial_exec[index % 16] = '_';
    index++;
    printf("%d ", index);
    printf("%s\n", buffer_initial_exec);
}
