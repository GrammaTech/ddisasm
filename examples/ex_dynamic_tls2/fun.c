#include <stdio.h>

// This test is to check if multiple symbols with the same name are
// correctly disambiguated.
//
// In this test example, foo.c also defines a static variable named as
// `buffer`.
//
// For fun.so built with -O2, Ddisasm should generate the following:
//   leaq buffer_disambig_XXXX_0@TLSLD(%rip),%rdi
//   callq __tls_get_addr@PLT
//
// The symbol `buffer` in the load instruction should be correctly
// distinguished from the `buffer` defined in foo.o.

static __thread char buffer[10];

void fun()
{
    for(int i = 0; i < 9; ++i)
    {
        buffer[i] = 0x41 + i;
    }
    buffer[9] = 0;
    printf("%s\n", buffer);
    return;
}
