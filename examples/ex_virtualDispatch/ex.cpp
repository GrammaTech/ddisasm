#include <stdio.h>
#include <stdlib.h>

class a
{
public:
    virtual void print() = 0;
};

class a1 : public a
{
public:
    virtual void print();
};

class a2 : public a
{
public:
    virtual void print();
};

void a1::print()
{
    puts("A1");
}

void a2::print()
{
    puts("A2");
}

int main()
{
    a1 a1;
    a2 a2;

    a* a = &a1;
    a->print();
    a = &a2;
    a->print();
    return 0;
}
