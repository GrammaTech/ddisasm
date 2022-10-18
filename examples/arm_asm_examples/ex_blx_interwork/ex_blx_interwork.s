.syntax unified
.section .text

.arm
.global	main
.type	main, %function
main:
    push { lr }

    ldr r0, litpool
    blx fun

    mov r0, #0
    pop { lr }
    bx lr

.thumb
.global fun
.type   fun, %function
fun:
    push { lr }

    bl printf

    pop { lr }
    bx lr

litpool:
    .word my_str

.section .data

my_str:
.string "Hello World\n"
