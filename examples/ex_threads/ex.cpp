#include <iostream>
#include <thread>

thread_local int threadLocal = 0;

void foo()
{
    std::cout << "foo " << threadLocal << std::endl;
    threadLocal++;
}

void bar(int x)
{
    std::cout << "bar " << threadLocal << std::endl;
    threadLocal++;
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
