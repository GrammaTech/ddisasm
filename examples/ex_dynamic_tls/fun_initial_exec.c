#include <stdio.h>

// By setting these variables to the initial-exec tls model
// the library will be marked with the STATIC_TLS flag in the dynamic section.

__attribute((tls_model("initial-exec"))) static __thread int index;
__attribute((tls_model("initial-exec"))) static __thread char buffer_initial_exec[16];

void fun_initial_exec()
{
    buffer_initial_exec[index % 16] = '_';
    index++;
    printf("%d ", index);
    printf("%s\n", buffer_initial_exec);
}
