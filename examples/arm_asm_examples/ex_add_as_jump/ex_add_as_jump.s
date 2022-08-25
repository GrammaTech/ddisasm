.syntax unified
.section .text

.global	main
.type	main, %function
main:
    ldr r12, [pc]
.add:
    add pc, r12, pc

    .long do_print-(.add+8)
.L2:
    .long str

.global	do_print
.type   do_print, %function
do_print:
    push { lr }
    ldr r0, .L2
    blx printf
    mov r0, #0
    pop { pc }

#===================================
.section .rodata ,"a",%progbits
#===================================

.align 2
str:
    .string "hello world\n"
