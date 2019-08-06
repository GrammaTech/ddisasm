#include <iostream>
#include <thread>

thread_local int i = 0;

void foo()
{
    std::cout << "foo " << i << std::endl;
    i++;
}

void bar(int x)
{
    std::cout << "bar " << i << std::endl;
    i++;
}

int main()
{
    std::cout << "foo and bar will be executed\n";
    std::thread first(foo);
    first.join();
    std::thread second(bar, 0);
    second.join();
    std::cout << "foo and bar completed.\n";
    return 0;
}
