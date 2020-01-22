// Adapted from http://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=100473
// switch2.cpp

#include <stdio.h>

void f1(int i) { printf("single-table-lookup-%c-1\n", 'A'+i); }
void f2(int i) { printf("single-table-lookup-%c-2\n", 'A'+i); }
void f3() { printf("single-table-lookup-default\n"); }

int main(int argc, char *argv[]) {
    int i = 0;

    if (argc != 2) {
        return 1;
    }

    i = argv[1][0] - 'A';

    switch (i) {
    case 0: f1(i); break;
    case 1: f1(i); break;
    case 2: f2(i); break; // C
    case 3: f1(i); break;
    case 4: f1(i); break;
    case 5: f1(i); break;
    case 6: f1(i); break;
    case 7: f1(i); break;
    case 8: f2(i); break; // I
    case 9: f1(i); break;

    case 10: f1(i); break;
    case 11: f1(i); break;
    case 12: f2(i); break; // M
    case 13: f1(i); break;
    case 14: f1(i); break;
    case 15: f1(i); break;
    case 16: f1(i); break;
    case 17: f1(i); break;
    case 18: f2(i); break; // S
    case 19: f1(i); break;

    case 20: f1(i); break;
    case 21: f1(i); break;
    case 22: f2(i); break; // W
    case 23: f1(i); break;
    case 24: f1(i); break;
    case 25: f1(i); break;
    default: f3();
    }

    return 0;
}
