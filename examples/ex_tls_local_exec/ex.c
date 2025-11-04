#include <stdio.h>

__thread int i __attribute__((tls_model("local-exec"))) = 4;

__thread int j __attribute__((tls_model("local-exec")));

__thread long k __attribute__((tls_model("local-exec"))) = 10;

__thread int l __attribute__((tls_model("local-exec")));

int foo()
{
    i++;
    printf("%d\n", i);
    j++;
    printf("%d\n", j);
    k++;
    printf("%ld\n", k);
    l++;
    printf("%d\n", l);

    return i + j + k + l;
}

int main()
{
    int n = foo();
    printf("foo() = %d\n", n);
    return 0;
}
