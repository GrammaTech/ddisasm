#include <stdio.h>
#include <stdlib.h>

class a
{
public:
    // int m[8]={25,255,25,255,25,255,255,25};
    virtual void print();
    virtual void print2();
    virtual void choose(int which);
};

void a::print()
{
    puts("A1");
}

void a::print2()
{
    puts("A2");
}

typedef void (a::*FPTR)();
void a::choose(int which)
{
    FPTR fptr[4] = {&a::print, &a::print2, &a::print, &a::print};
    FPTR sel = fptr[which];
    (this->*sel)();
}

int main()
{
    a *a1;
    a1 = new a();
    a1->choose(0);
    a1->choose(1);
    a1->choose(2);
    a1->choose(3);
    return 0;
}
