.set noreorder
.set noat

.text

.global _start
_start:
    lui $gp,%hi(_gp)
    addiu $gp,$gp,%lo(_gp)
    move $ra,$zero
    lw $a0,%got(main)($gp)
    lw $a1,0($sp)
    addiu $a2,$sp,4
    addiu $at,$zero,-8
    and $sp,$sp,$at
    addiu $sp,$sp,-32
    lw $a3,%got(__libc_csu_init)($gp)
    lw $t0,%got(__libc_csu_fini)($gp)
    sw $t0,16($sp)
    sw $v0,20($sp)
    sw $sp,24($sp)
    lw $t9,%got(__libc_start_main)($gp)
    jalr $t9
    nop

.globl main
.type main, @function
main:
    addiu $sp,$sp,-32
    sw $ra,28($sp)

    lui $gp,%hi(_gp)
    addiu $gp,$gp,%lo(_gp)

    # call fun via got with split load
    lw $t9,%got_page(fun)($gp)
    addiu $t9,$t9,%got_ofst(fun)
    jalr $t9
    nop

    move $v0, $zero

    lw $ra,28($sp)
    jr $ra
    addiu $sp,$sp,32

.globl fun
.type fun, @function
fun:
    addiu $sp,$sp,-32
    sw $ra,28($sp)

    # puts("hello world")

    lui $v0,%hi(message)
    addiu $a0,$v0,%lo(message)

    lui $gp,%hi(_gp)
    addiu $gp,$gp,%lo(_gp)
    lw $v0,%got(puts)($gp)
    move $t9,$v0
    jalr $t9
    nop

    lw $ra,28($sp)
    addiu $sp,$sp,32
    jr $ra
    nop

.section .rodata
message:
    .string "Hello world"
