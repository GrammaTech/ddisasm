/**
This dynamic library has many internal symbols, and references many library
functions.
*/

#include <math.h>
#include <stdio.h>

void fun(int a, int b)
{
    int i = 0;
    while(a < b)
    {
        ++i;
        ++a;
        printf("%i\n", i);
    }
}

void fun1(float x)
{
    float y = tanf(x);
    printf("%f\n", x);
}

void fun2(double x)
{
    double y = tan(x);
    printf("%f\n", x);
}

void fun3(long double x)
{
    long double y = tanl(x);
    printf("%Lf\n", x);
}

void fun4(float x)
{
    float y = sinf(x);
    printf("%f\n", x);
}

void fun5(double x)
{
    double y = sin(x);
    printf("%f\n", x);
}

void fun6(long double x)
{
    long double y = sinl(x);
    printf("%Lf\n", x);
}

void fun7(float x)
{
    float y = cosf(x);
    printf("%f\n", x);
}

void fun8(double x)
{
    double y = cos(x);
    printf("%f\n", x);
}

void fun9(long double x)
{
    long double y = cosl(x);
    printf("%Lf\n", x);
}

void fun10(float x)
{
    float y = asinf(x);
    printf("%f\n", x);
}

void fun11(double x)
{
    double y = asin(x);
    printf("%f\n", x);
}

void fun12(long double x)
{
    long double y = asinl(x);
    printf("%Lf\n", x);
}

void fun13(float x)
{
    float y = acosf(x);
    printf("%f\n", x);
}

void fun14(double x)
{
    double y = acos(x);
    printf("%f\n", x);
}

void fun15(long double x)
{
    long double y = acosl(x);
    printf("%Lf\n", x);
}

void fun16(float x)
{
    float y = atanf(x);
    printf("%f\n", x);
}

void fun17(double x)
{
    double y = atan(x);
    printf("%f\n", x);
}

void fun18(long double x)
{
    long double y = atanl(x);
    printf("%Lf\n", x);
}

void fun19(float x)
{
    float y = expf(x);
    printf("%f\n", x);
}

void fun20(double x)
{
    double y = exp(x);
    printf("%f\n", x);
}

void fun21(long double x)
{
    long double y = expl(x);
    printf("%Lf\n", x);
}

void fun22(float x)
{
    float y = sqrtf(x);
    printf("%f\n", x);
}

void fun23(double x)
{
    double y = sqrt(x);
    printf("%f\n", x);
}

void fun24(long double x)
{
    long double y = sqrtl(x);
    printf("%Lf\n", x);
}

void fun_all(float x)
{
    fun1(x);
    fun2(x);
    fun3(x);
    fun4(x);
    fun5(x);
    fun6(x);
    fun7(x);
    fun8(x);
    fun9(x);
    fun10(x);
    fun11(x);
    fun12(x);
    fun13(x);
    fun14(x);
    fun15(x);
    fun16(x);
    fun17(x);
    fun18(x);
    fun19(x);
    fun20(x);
    fun21(x);
    fun22(x);
    fun23(x);
    fun24(x);
}
