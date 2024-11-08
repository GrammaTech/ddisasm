#include <stdio.h>
#include <stdlib.h>

class a
{
public:
    void foo();

private:
    __attribute__((visibility("hidden"))) void bar();
    void baz() __attribute__((weak));
};

void a::foo()
{
    printf("foo\n");
    this->bar();
    this->baz();
}

void a::bar()
{
    printf("bar\n");
}

void a::baz()
{
    printf("baz\n");
}

int main()
{
    a *a1;
    a1 = new a();
    a1->foo();
    return 0;
}
