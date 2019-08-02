#include <exception>
#include <iostream>

class myException : std::logic_error
{
public:
    myException(const std::string& msg) : std::logic_error(msg)
    {
    }
    std::string what()
    {
        return std::logic_error::what();
    }
};

void f1(int counter)
{
    try
    {
        if(counter == 0)
            throw myException("exception");
        else
            f1(counter - 1);
    }
    catch(myException& e)
    {
        std::cout << e.what();
        std::cout << " catched in level " << counter << std::endl;
        throw myException("exception thrown in level " + std::to_string(counter));
    }
}

void f2()
{
    try
    {
        f1(10);
    }
    catch(myException& e)
    {
        std::cout << e.what();
        std::cout << " catched in f2" << std::endl;
    }
}
int main()
{
    f2();
    return 0;
}
