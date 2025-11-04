#include <stdio.h>

__thread int initialized1 __attribute__((tls_model("local-exec"))) = 4;

__thread int uninitialized1 __attribute__((tls_model("local-exec")));

__thread long initialized2 __attribute__((tls_model("local-exec"))) = 10;

__thread int uninitialized2 __attribute__((tls_model("local-exec")));

int foo()
{
    initialized1++;
    printf("%d\n", initialized1);
    uninitialized1++;
    printf("%d\n", uninitialized1);
    initialized2++;
    printf("%ld\n", initialized2);
    uninitialized2++;
    printf("%d\n", uninitialized2);

    return initialized1 + uninitialized1 + initialized2 + uninitialized2;
}

int main()
{
    int n = foo();
    printf("foo() = %d\n", n);
    return 0;
}
