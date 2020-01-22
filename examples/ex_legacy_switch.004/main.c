// Adapted from http://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=100473
// switch2.cpp

#include <stdio.h>

void f1(const char *s) { printf("hybrid-table-lookup-%s\n", s); }
void f2(const char *s) { printf("hybrid-table-lookup-%s\n", s); }
void f3(const char *s) { printf("hybrid-lookup-default-%s\n", s); }

int main(int argc, char *argv[]) {
    int i = 0;

    if (argc == 2 &&
        argv[1][0] != '\0' &&
        argv[1][1] != '\0' &&
        argv[1][2] != '\0') {

        // Note, this is not guaranteed to use digits, but it doesn't matter
        i = (argv[1][0]-'0')*100 + (argv[1][1]-'0')*10 + (argv[1][2]-'0');

        if (i < 500) {
            switch (i) {
            case 3: f1("A"); break;
            case 4: f1("B"); break;
            case 5: f2("C"); break;
            case 6: f2("D"); break;
            case 7: f2("E"); break;
            case 8: f1("F"); break;
            case 9: f1("G"); break;
            case 10: f1("H"); break;
            case 11: f2("I"); break;
            case 12: f2("J"); break;
            case 13: f2("K"); break;
            case 14: f1("L"); break;
            case 15: f1("M"); break;
            case 16: f1("N"); break;
            case 17: f2("O"); break;
            case 18: f2("P"); break;
            case 19: f2("Q"); break;
            case 20: f1("R"); break;
            default: f3("0");
            }
        }
        else if (i > 750) {
            switch(i) {
            case 903: f1("A2"); break;
            case 904: f1("B2"); break;
            case 905: f2("C2"); break;
            case 906: f2("D2"); break;
            case 907: f2("E2"); break;
            case 908: f1("F2"); break;
            case 909: f1("G2"); break;
            case 910: f1("H2"); break;
            case 911: f2("I2"); break;
            case 912: f2("J2"); break;
            case 913: f2("K2"); break;
            case 914: f1("L2"); break;
            case 915: f1("M2"); break;
            case 916: f1("N2"); break;
            case 917: f2("O2"); break;
            case 918: f2("P2"); break;
            case 919: f2("Q2"); break;
            case 920: f1("R2"); break;
            default: f3("2");
            }
        }
        else {
            switch(i) {
            case 603: f1("A1"); break;
            case 604: f1("B1"); break;
            case 605: f2("C1"); break;
            case 606: f2("D1"); break;
            case 607: f2("E1"); break;
            case 608: f1("F1"); break;
            case 609: f1("G1"); break;
            case 610: f1("H1"); break;
            case 611: f2("I1"); break;
            case 612: f2("J1"); break;
            case 613: f2("K1"); break;
            case 614: f1("L1"); break;
            case 615: f1("M1"); break;
            case 616: f1("N1"); break;
            case 617: f2("O1"); break;
            case 618: f2("P1"); break;
            case 619: f2("Q1"); break;
            case 620: f1("R1"); break;
            default: f3("1");
            }
        }
    }

    return 0;
}
