    .text

    .globl  main
    .type   main, @function
main:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
	movl	$mystring, %edi
	call	puts
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main

.align 8
    .data

    .quad mydata
    .zero 8
    # 0x512350 happens to be the address of `_start` (see the Makefile).
    # This example is to test that this address is not symbolized as `_start`
    # This program is supposed to print out "#Q".
    # If this address is symbolized as `_start`,
    # it will print out something else.
    .ascii "P"   # 0x50
mystring:
    .string "#Q" # 0x23 0x51
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0

mydata:
    .zero 16
