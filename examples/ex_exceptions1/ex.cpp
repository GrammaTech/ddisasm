#include <exception>
#include <iostream>

int main()
{
    try
    {
        throw std::logic_error("This is a logic error");
    }
    catch(std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
