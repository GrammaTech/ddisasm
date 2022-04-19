
#include <iostream>
#include <string>

class Cl1
{
private:
    std::string msg;

public:
    Cl1(const char* msg) : msg(msg)
    {
        std::cout << msg << std::endl;
    }
    ~Cl1()
    {
        std::cout << "bye " << msg << std::endl;
    }
};
