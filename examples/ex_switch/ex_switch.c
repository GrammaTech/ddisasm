#include <stdio.h>
#include <stdlib.h>

int one(int a){
    return a;
}
int two(int a){
    return a;
}
int three(int a){
    return a+1;
}
int four(int a){
    return a;
}
int def(int a){
    return a;
}


void fun(int a,int b){
        switch(a){
        case 1:
            one(a);
            break;
        case 2:
            two(a);
            break;
        case 3:
            three(a);
        case 4:
            four(a);
            break;
        default:
            def(a);
            
        }
}
int main() {
    fun(3,20);
    puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
    puts("a"); /* prints !!!Hello World!!! */
    puts("b"); /* prints !!!Hello World!!! */
    puts("c"); /* prints !!!Hello World!!! */
 return 0;
}

