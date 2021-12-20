.syntax unified
.section .text

.global	main
.type	main, %function
main:
    push {lr}

    setend be
    ldr r1, myword
    setend le

    ldr r0, =print_format
    bl printf

    mov r0, #0
    pop {pc}

myword:
    .long 0xDEADBEEF

.section .rodata
print_format:
    .ascii "%x\n\0"
