#include <stdint.h>

typedef struct
{
    int32_t arr[10];
    void (*fun_ptr)(const char*);
    int32_t v;
    const char** str;
    int32_t arr2[5];
} A;

void fun(A*);
