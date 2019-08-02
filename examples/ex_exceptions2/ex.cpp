#include <exception>
#include <iostream>

void f1(bool throwExc)
{
    if(throwExc)
        throw std::invalid_argument("This is an invalid argument");
}

void f2(bool throwExc, bool throwExc2)
{
    try
    {
        f1(throwExc);
        if(throwExc2)
            throw std::domain_error("This is a domaing error");
        throw std::logic_error("This is a logic error");
    }
    catch(std::invalid_argument& e)
    {
        std::cout << e.what() << std::endl;
    }
    catch(std::domain_error& e)
    {
        std::cout << e.what() << std::endl;
    }
}

int main()
{
    try
    {
        f2(true, true);
        f2(false, true);
        f2(false, false);
    }
    catch(std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
