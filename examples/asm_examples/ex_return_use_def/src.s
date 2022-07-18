#===================================
.text
#===================================

#-----------------------------------
.type get_ptr, @function
#-----------------------------------
get_ptr:

.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
            movq hello(%rip),%rax
            cmpl $0,count(%rip)
            jle .L_1160

            movq goodbye(%rip),%rax
.L_1160:

            cmpb $32,(%rax)
            je .L_1168

            movb $32,(%rax)
.L_1168:

            addl $1,count(%rip)
            retq
.cfi_endproc
.align 16
#-----------------------------------
.globl main
.type main, @function
#-----------------------------------
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
            subq $8,%rsp
.cfi_def_cfa_offset 16
            callq get_ptr

            testq %rax,%rax
            je .L_118a

            movq %rax,%rdi
            callq puts@PLT
.L_118a:

            callq get_ptr

            movq %rax,%rdi
            testq %rax,%rax
            je .L_119c

            callq puts@PLT
.L_119c:

            movl $0,%eax
            addq $8,%rsp
.cfi_def_cfa_offset 8
            retq
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
#===================================
# end section .text
#===================================

#===================================
.data
#===================================

.align 8
#-----------------------------------
.globl goodbye
.type goodbye, @object
#-----------------------------------
goodbye:
          .quad .L_2004
#-----------------------------------
.globl hello
.type hello, @object
#-----------------------------------
hello:
          .quad .L_2013

.L_2004:
          .string "-Goodbye World"
.L_2013:
          .string "-Hello World"

#===================================
# end section .data
#===================================

#===================================
.bss
#===================================

.align 4
#-----------------------------------
.globl count
.type count, @object
#-----------------------------------
count:
          .zero 4

#===================================
# end section .bss
#===================================
