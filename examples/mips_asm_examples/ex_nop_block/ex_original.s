.set noreorder
.set noat

#===================================
.section .note.ABI-tag ,"a"
#===================================

.align 2
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x4
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x10
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x1
          .byte 0x47
          .byte 0x4e
          .byte 0x55
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x3
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x2
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
#===================================
# end section .note.ABI-tag
#===================================

#===================================
.text
#===================================

.align 2
#-----------------------------------
.globl FUN_40060c
.type FUN_40060c, @function
#-----------------------------------
FUN_40060c:

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
hlt:

            b hlt
            nop
          .zero 8
.align 4
#-----------------------------------
.globl foobar
.type foobar, @function
#-----------------------------------
foobar:

            addiu $sp,$sp,-32
            sw $ra,28($sp)
            sw $fp,24($sp)
            move $fp,$sp
            lui $gp,%hi(_gp)
            addiu $gp,$gp,%lo(_gp)
            sw $gp,16($sp)
            sw $a0,32($fp)
            sw $a1,36($fp)
            lw $v0,32($fp)
            mtc1 $v0,$f0
            cvt.d.w $f2,$f0
            lui $v0,%hi(.L_400bb0)
            ldc1 $f0,%lo(.L_400bb0)($v0)
            mov.d $f14,$f2
            mov.d $f12,$f0
            lw $v0,%got(pow)($gp)
            move $t9,$v0
            jalr $t9
            nop

            lw $gp,16($fp)
            lw $v0,32($fp)
            sll $v0,$v0,2
            lw $v1,36($fp)
            addu $v0,$v1,$v0
            trunc.w.d $f0,$f0
            mfc1 $v1,$f0
            sw $v1,0($v0)
            lw $v0,32($fp)
            sll $v0,$v0,2
            lw $v1,36($fp)
            addu $v0,$v1,$v0
            lw $v0,0($v0)
            lw $a2,32($fp)
            move $a1,$v0
            lui $v0,%hi(.L_400b80)
            addiu $a0,$v0,%lo(.L_400b80)
            lw $v0,%got(printf)($gp)
            move $t9,$v0
            jalr $t9
            nop

            lw $gp,16($fp)
            nop
            move $sp,$fp
            lw $ra,28($sp)
            lw $fp,24($sp)
            addiu $sp,$sp,32
            jr $ra
            nop
.align 2
#-----------------------------------
.globl Entry
.type Entry, @function
#-----------------------------------
Entry:

            addiu $sp,$sp,-40
            sw $ra,36($sp)
            sw $fp,32($sp)
            move $fp,$sp
            sw $a0,40($fp)
            lui $v0,%hi(foobar)
            addiu $v0,$v0,%lo(foobar)
            sw $v0,24($fp)
            sw $zero,28($fp)
            b .L_4008b0
            nop
.L_400890:

            lui $v0,%hi(global_var)
            addiu $a1,$v0,%lo(global_var)
            lw $a0,28($fp)
            jal foobar
            nop

            lw $v0,28($fp)
            addiu $v0,$v0,1
            sw $v0,28($fp)
.L_4008b0:

            lw $v1,28($fp)
            lw $v0,40($fp)
            slt $v0,$v1,$v0
            bnez $v0,.L_400890
            nop

# Initially (A) and (B) are recognized as one block, and later split.
# `block_has_non_nop` should hold on (B), and it should not be recognized
# as `nop_block`.
# (A)
            nop
            nop
# (B)
            move $sp,$fp
            lw $ra,36($sp)
            lw $fp,32($sp)
            addiu $sp,$sp,40
            jr $ra
            nop
.align 2
#-----------------------------------
.globl main
.type main, @function
#-----------------------------------
main:

            addiu $sp,$sp,-32
            sw $ra,28($sp)
            sw $fp,24($sp)
            move $fp,$sp
            lui $gp,%hi(_gp)
            addiu $gp,$gp,%lo(_gp)
            sw $gp,16($sp)
            sw $a0,32($fp)
            sw $a1,36($fp)
            lw $v0,32($fp)
            slti $v0,$v0,2
            beqz $v0,.L_400954
            nop

            lw $v0,%got(stderr)($gp)
            lw $v0,0($v0)
            move $a3,$v0
            addiu $a2,$zero,24
            addiu $a1,$zero,1
            lui $v0,%hi(.L_400b94)
            addiu $a0,$v0,%lo(.L_400b94)
            lw $v0,%got(fwrite)($gp)
            move $t9,$v0
            jalr $t9
            nop

            lw $gp,16($fp)
            addiu $v0,$zero,1
            b .L_40098c
            nop
.L_400954:

            lw $v0,36($fp)
            addiu $v0,$v0,4
            lw $v0,0($v0)
            move $a0,$v0
            lw $v0,%got(atoi)($gp)
            move $t9,$v0
            jalr $t9
            nop

            lw $gp,16($fp)
            move $a0,$v0
            jal Entry
            nop

            lw $gp,16($fp)
            move $v0,$zero
.L_40098c:

            move $sp,$fp
            lw $ra,28($sp)
            lw $fp,24($sp)
            addiu $sp,$sp,32
            jr $ra
            nop
          .zero 12
#===================================
# end section .text
#===================================

#===================================
.section .rodata ,"a",@progbits
#===================================

.align 4
.L_400b70:
          .byte 0x0
          .byte 0x2
          .byte 0x0
          .byte 0x1
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
.L_400b80:
          .string "Wrote %d to [%d]\n"
          .zero 2
.L_400b94:
          .string "Pass in an integer <100\n"
          .zero 3
.L_400bb0:
          .byte 0x40
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
#===================================
# end section .rodata
#===================================

#===================================
.data
#===================================

.align 4
#-----------------------------------
.globl _fdata
.type _fdata, @notype
#-----------------------------------
_fdata:
          .zero 16
#===================================
# end section .data
#===================================

#===================================
.bss
#===================================

.align 4
#-----------------------------------
.type completed.7134, @object
.size completed.7134, 1
#-----------------------------------
completed.7134:
#-----------------------------------
.globl _fbss
.type _fbss, @notype
#-----------------------------------
_fbss:
          .zero 4
#-----------------------------------
.type dtor_idx.7136, @object
.size dtor_idx.7136, 4
#-----------------------------------
dtor_idx.7136:
          .zero 12
#-----------------------------------
.type global_var, @object
.size global_var, 400
#-----------------------------------
global_var:
          .zero 400
.L_411220:
#-----------------------------------
.globl _end
.type _end, @notype
#-----------------------------------
_end:
#===================================
# end section .bss
#===================================
#-----------------------------------
.symver stderr,stderr@GLIBC_2.0
.globl stderr
.type stderr, @object
#-----------------------------------
