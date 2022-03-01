.intel_syntax noprefix
.text
#-----------------------------------
.globl main
.type main, @function
#-----------------------------------
main:
	push RBX
load_end:
        mov RBX,OFFSET nums_end
beg_loop:
        cmp RBX,OFFSET nums_start
        jbe end_loop
        sub RBX,4
        movsx EDX,WORD PTR [RBX]
        lea RSI,QWORD PTR [RIP+format_string]
        xor EAX,EAX
        mov EDI,1
        call __printf_chk@PLT
        jmp beg_loop
end_loop:
	pop RBX
	xor EAX,EAX
	ret


#===================================
.section .rodata ,"a",@progbits
#===================================


format_string:
        .string "%i\n"

#===================================
# end section .rodata
#===================================

#===================================
.data
#===================================
nums_start:
	.long 1
	.long 2
	.long 3
	.long 4
#-----------------------------------
.globl nums_end
.type nums_end, @object
#-----------------------------------
nums_end:

.bss
#-----------------------------------
.globl other_stuff
.type other_stuff, @object
#-----------------------------------
other_stuff:
          .zero 10
