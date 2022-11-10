.arch armv7-a
.section .text
.align 2
.global main
.type main, %function
.thumb
main:
    push {r7, lr}
.thumb
    ldr r0, .L0
    # This address corresponds to _start+4, but it should not symbolize,
    # because this is a PIE binary.
    # Hopefully the compiler continues to generate the same addresses...
    movw r1, #0x409
    movt r1, #0

    bl printf
.thumb
    mov r0, #0
    pop {r7, pc}

.L0:
    .long print_format

.section .rodata
.align 2
print_format:
    .string "%x\n"
