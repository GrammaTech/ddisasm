#
# This function is to check if ddisasm finds a function entry after literal
# pools even if there is no symbol info nor direct calls to the function.
#
# The function `add` does not have any direct call to it.
# After stripped, `add` has no symbol information.
# It is placed right after the literal pool.
#

.arch armv7-a

.thumb
.text

.equ SYS_EXIT, 1
.equ SYS_WRITE, 4
.equ STDOUT, 1

@ Function: sum (calls a function via BLX r3)
.global sum
.type sum, %function
.thumb_func
sum:
    push {lr}        @ Save link register
    mov r3, r2       @ Store function pointer in r3
    blx r3           @ Call function pointer
    pop {pc}         @ Return

@ Print function: writes r0 as ASCII to stdout
.global print_result
.type print_result, %function
.thumb_func
print_result:
    push {r1-r3, lr}

    @ Convert number in r0 to ASCII ('0' + value)
    add r0, r0, #48      @ Convert to ASCII ('0' = 48)

    @ Load address of result using PC-relative addressing
    adr r3, result_ptr   @ Load address of result into r3
    ldr r3, [r3]         @ Dereference pointer to get real address
    strb r0, [r3, #8]    @ Store ASCII digit in result buffer

    @ Write "Result: X\n" to stdout
    mov r0, #STDOUT      @ fd = 1 (stdout)
    adr r1, result_ptr   @ Load result address using literal pool
    ldr r1, [r1]         @ Dereference pointer
    mov r2, #10          @ size = 10
    mov r7, #SYS_WRITE   @ syscall: write
    svc #0

    pop {r1-r3, pc}

@ Entry Point (_start)
.global _start
.type _start, %function
.thumb_func
_start:
    mov r0, #3       @ First argument (a)
    mov r1, #4       @ Second argument (b)
    adr r2, add_ptr  @ Load function pointer address
    ldr r2, [r2]     @ Dereference pointer
    bl sum           @ Call sum(a, b, add)

    bl print_result  @ Print the result

    mov r7, #SYS_EXIT  @ syscall: exit
    mov r0, #0         @ exit code 0
    svc #0

@ Literal Pool (for PC-relative addressing)
.ltorg
.align 4
result_ptr:  .word result
add_ptr:     .word add

@ Indirect call target
.type add, %function
.thumb_func
add:
    push {lr}
    add r0, r0, r1   @ r0 = r0 + r1
    pop {pc}

.data
result:
    .asciz "Result: X\n"
