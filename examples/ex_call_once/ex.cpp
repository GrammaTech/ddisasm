// https://en.cppreference.com/w/cpp/thread/call_once
#include <iostream>
#include <mutex>
#include <thread>

std::once_flag flag1;

void simple_do_once()
{
    std::call_once(flag1, []() { std::cout << "called once\n"; });
}

int main()
{
    std::thread st1(simple_do_once);
    std::thread st2(simple_do_once);
    std::thread st3(simple_do_once);
    std::thread st4(simple_do_once);
    st1.join();
    st2.join();
    st3.join();
    st4.join();

    return EXIT_SUCCESS;
}
