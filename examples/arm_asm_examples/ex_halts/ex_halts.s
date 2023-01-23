.syntax unified
.section .text
.thumb
.arch armv8-a

.global	main
.type	main, %function
main:
    push {lr}

    cmp r0, #10
    bgt halt
    bgt trap
    bgt udf

    ldr r0, =message
    bl printf

    mov r0, #0
    pop {pc}

halt:
    hlt

.long 0xffffffff

trap:
    udf 0xfe

.long 0xffffffff

udf:
    udf 0xff

.long 0xffffffff

.section .rodata
message:
    .asciz "Hello World!\n"
