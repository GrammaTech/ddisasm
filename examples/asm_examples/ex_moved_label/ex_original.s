// moved_label
// This is for a corner case as follows:
// E.g.,
//     lea r1, [.L_XXXX] // where XXXX points to a data object
// (A) lea r2, [.L_YYYY] // where YYYY points to the limit of the data object
//     // reg is computed with r1
//     cmp reg, r2
//     ...
//     .L_XXXX: ...
//     ...
//     .L_YYYY: // indicate the last address of the object at .L_XXXX
// It is fine if .L_YYYY remains. However, if .L_YYYY is a label that is
// eventually removed during rewriting, such as .eh_frame, .eh_frame_hdr, etc.,
// we want to adjust (A) instruction as follows:
// (A')lea r2, [.L_XXXX + size_of_object]

    .file	"ex_original.c"
    .intel_syntax noprefix
    .section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
    .string	"%i \n"
.LC1:
    .string	"%lu \n"
    .section	.text.unlikely,"ax",@progbits
.LCOLDB2:
    .section	.text.startup,"ax",@progbits
.LHOTB2:
    .p2align 4,,15
    .globl	main
    .type	main, @function
main:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
            nop
            nop
            nop
            nop
            push RAX
.cfi_def_cfa_offset 16
            lea RDI,QWORD PTR [RIP+.L_2008]
            call puts@PLT

            xor EAX,EAX
            call print

            xor EAX,EAX
            pop RDX
.cfi_def_cfa_offset 8
            ret
.cfi_endproc

            nop
            nop
            nop
            nop
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x66
          .byte 0xf
          .byte 0x1f
          .byte 0x44
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x0
          .byte 0xf
          .byte 0x1f
          .byte 0x80
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
#-----------------------------------
.globl print
.type print, @function
#-----------------------------------
print:

.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
            nop
            nop
            nop
            nop
            push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
point.1:
            lea RBP,QWORD PTR [RIP+array_end] # Expect to be point.2+22
point.3:
            push RBX
.cfi_def_cfa_offset 24
.cfi_offset 3, -24
            lea RBX,QWORD PTR [RIP+array]
            push RDX
.L_119e:

.cfi_def_cfa_offset 32
            cmp RBX,RBP
            jae .L_11bf

            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+.L_2004]
            xor EAX,EAX
            add RBX,2
            mov EDI,1
            call __printf_chk@PLT

            jmp .L_119e
.L_11bf:

            pop RAX
.cfi_def_cfa_offset 24
            pop RBX
.cfi_def_cfa_offset 16
            pop RBP
.cfi_def_cfa_offset 8
            ret
.cfi_endproc

            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
#===================================
# end section .text
#===================================

#===================================
.section .rodata ,"a",@progbits
#===================================

.align 4
          .byte 0x1
          .byte 0x0
          .byte 0x2
          .byte 0x0
.L_2004:
          .string "%i\n"
.L_2008:
          .string "Printing data"
#===================================
# end section .rodata
#===================================

#===================================
.data
#===================================

.align 16
#-----------------------------------
.weak data_start
.type data_start, @notype
#-----------------------------------
data_start:
          .zero 8
          .quad 0
#-----------------------------------
.globl array
.type array, @object
#-----------------------------------
array:
          .byte 0xa
          .byte 0x0
point.2:
          .byte 0xb
          .byte 0x0
          .byte 0xc
          .byte 0x0
          .byte 0xa3
          .byte 0x5
          .byte 0x40
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x11
          .byte 0x0
          .byte 0x12
          .byte 0x0
          .byte 0x13
          .byte 0x0
          .byte 0x14
          .byte 0x0
#-----------------------------------
.globl array_end
.type array_end, @notype
#-----------------------------------
array_end:
#-----------------------------------
.globl _edata
.type _edata, @notype
#-----------------------------------
_edata:
#-----------------------------------
.globl edata
.type edata, @notype
#-----------------------------------
edata:
#===================================
# end section .data
#===================================

#===================================
.bss
#===================================

.align 16
completed.8060:
          .zero 16
#-----------------------------------
.globl _end
.type _end, @notype
#-----------------------------------
_end:
#===================================
# end section .bss
#===================================
