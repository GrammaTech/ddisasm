#include <stdio.h>

/*
NOTE: This example is designed to produce the following PLT entry:
   #===================================
   .section .plt.sec ,"ax",@progbits
   #===================================
   #-----------------------------------
   .globl fun
   .type fun, @function
   #-----------------------------------
   fun:
         401070:   endbr64
         401074:   bnd jmp QWORD PTR [RIP+.L_404020]
   .size fun, . - fun

   #===================================
   .section .got.plt ,"wa",@progbits
   #===================================
   .L_404020:
         404020: .quad fun

This C program must be compiled with `-fno-PIC` and linked with `-no-pie`
(see the Makefile).

1. -fno-PIC: Forces the compiler to treat the address of `fun` as a fixed
   absolute constant.

2. -no-pie: Prevents the linker from making the binary position-independent,
   allowing the symbol `fun` to have a static VMA (Virtual Memory Address).

3. Function pointer: By taking the address `(void*)fun`, we force the Linker
   to create a `Canonical PLT`. Because the linker doesn't know the real
   address of `fun` (it's in fun.so), it uses the address of the PLT stub
   as the function's identity to satisfy the absolute resolution.
*/

// External function defined in fun.so
extern void fun();

int main()
{
    puts("Calling fun...");

    // Standard call
    fun();

    // Address-of: Forces the .dynsym address to be non-zero (Canonical PLT).
    // The linker stamps the PLT address (e.g., 0x401070) into the symbol table
    // so taht `&fun` returns the same pointer value throughout the execution.
    printf("Canonical PLT address of fun: %p\n", (void*)fun);

    return 0;
}
