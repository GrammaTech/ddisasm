#include <stdio.h>
#include "test.h"

__declspec(dllexport) void message() {
  puts("hello dll");
}
