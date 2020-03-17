#include <stdio.h>
#include <stdlib.h>

void fun(int a, int b)
{
    float fl = 4567765;
    double dbl = 984753;
    int64_t i64 = 98438765876587657;
    int32_t i32 = 98437;
    int16_t i16 = 984;
    char ch = 5;

    while(a < b)
    {
        ++a;
        ++fl;
        ++dbl;
        i64++;
        i32++;
        i16++;
        ch++;
    }
    printf("%f\n", fl);
    printf("%f\n", dbl);

    printf("%li\n", i64);
    printf("%i\n", i32);
    printf("%i\n", i16);
    printf("%c\n", ch);
}
int main()
{
    puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
    fun(10, 20);
    return 0;
}
