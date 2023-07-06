// moved_label immediate
// Each print* function has a different kind of loop
// that requires immediate moved labels or boundary_sym_expr.


    .intel_syntax noprefix
    .globl	main
    .type	main, @function
main:

            push RAX
            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print

            lea RDI,QWORD PTR [RIP+msg2]
            call puts@PLT
            xor EAX,EAX
            call print_descending

            lea RDI,QWORD PTR [RIP+msg2]
            call puts@PLT
            xor EAX,EAX
            call print_descending_mov

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_above

            lea RDI,QWORD PTR [RIP+msg2]
            call puts@PLT
            xor EAX,EAX
            call print_below

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_above_mov

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_above_loaded_pc

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_below_ascending

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_below_ascending_pc

            lea RDI,QWORD PTR [RIP+msg1]
            call puts@PLT
            xor EAX,EAX
            call print_above_descending

            xor EAX,EAX
            pop RDX
            ret

#-----------------------------------
.globl print
.type print, @function
#-----------------------------------
print:
            push RBP
            push RBX

# The loop bound starts at the end of the section

            lea RBP,QWORD PTR [RIP+array_end]
            lea RBX,QWORD PTR [RIP+array]
loop_back:
            cmp RBX,RBP
            jae end_loop
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            add RBX,2
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back
end_loop:
            pop RBX
            pop RBP
            ret


#-----------------------------------
.globl print_descending
.type print_descending, @function
#-----------------------------------
print_descending:
            push RBP
            push RBX

# The loop counter starts at the end of the section

            lea RBX,QWORD PTR [RIP+array_end]
            lea RBP,QWORD PTR [RIP+array]
des_loop_back:
            sub RBX,2
            cmp RBX,RBP
            jb des_end_loop
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp des_loop_back
des_end_loop:
            pop RBX
            pop RBP
            ret

#-----------------------------------
.globl print_descending_mov
.type print_descending_mov, @function
#-----------------------------------
print_descending_mov:
            push RBP
            push RBX
# The loop counter starts at the end of the section
# and it is loaded with a mov instruction
            mov RBX, offset array_end
            lea RBP,QWORD PTR [RIP+array]
des_loop_back_mov:
            sub RBX,2
            cmp RBX,RBP
            jb des_end_loop
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp des_loop_back_mov
des_end_loop_mov:
            pop RBX
            pop RBP
            ret


#-----------------------------------
.globl print_above
.type print_above, @function
#-----------------------------------
print_above:
            push RBX
            lea RBX,QWORD PTR [RIP+array]
loop_back_above:
            add RBX,2

# The loop boundary is an immediate above the
# end of the section

            cmp RBX, offset array_end+2
            jae end_loop_above
            movsx EDX,WORD PTR [RBX-2]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_above
end_loop_above:
            pop RBX
            ret

#-----------------------------------
.globl print_below
.type print_below, @function
#-----------------------------------
print_below:
            push RBX
            mov RBX, offset array_end_data2
loop_back_below:
            sub RBX,2

# The loop boundary is an immediate below
# the beginning of the section

            cmp RBX, offset array_data2-2
            jbe end_loop_below
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_below
end_loop_below:
            pop RBX
            ret

#-----------------------------------
.globl print_above_mov
.type print_above_mov, @function
#-----------------------------------
print_above_mov:
            push RBX
            push RBP

# The loop boundary is loaded into a register
# and it is above the end of the section

            mov RBP, offset array_end+2
            mov RBX, offset array
loop_back_above_mov:
            add RBX,2
            cmp RBX, RBP
            jae end_loop_above_mov
            movsx EDX,WORD PTR [RBX-2]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_above_mov
end_loop_above_mov:
            pop RBP
            pop RBX
        ret

#-----------------------------------
.globl print_above_loaded_pc
.type print_above_loaded_pc, @function
#-----------------------------------
print_above_loaded_pc:
            push RBX
            push RBP

# The loop boundary is loaded into a register
# with a pc-relative operand and it is above the end of the section

            lea RBP, QWORD PTR [RIP+array_end+2]
            mov RBX, offset array
loop_back_above_loaded_pc:
            add RBX,2
            cmp RBX, RBP
            jae end_loop_above_loaded_pc
            movsx EDX,WORD PTR [RBX-2]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_above_loaded_pc
end_loop_above_loaded_pc:
            pop RBP
            pop RBX
        ret

#-----------------------------------
.globl print_below_ascending
.type print_below_ascending, @function
#-----------------------------------
print_below_ascending:
            push RBX

# The loop counter starts below the beginning
# of the section

            mov RBX, offset array_data2-2
loop_back_below_ascending:
            add RBX,2
            cmp RBX, offset array_end_data2
            je end_loop_below_ascending
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_below_ascending
end_loop_below_ascending:
            pop RBX
        ret

#-----------------------------------
.globl print_below_ascending_pc
.type print_below_ascending_pc, @function
#-----------------------------------
print_below_ascending_pc:
            push RBX

# The loop counter starts below the beginning
# of the section. The counter is loaded with
# a pc-relative operand.

            lea RBX, QWORD PTR [RIP+array_data2-2]
loop_back_below_ascending_pc:
            add RBX,2
            cmp RBX, offset array_end_data2
            je end_loop_below_ascending_pc
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_below_ascending_pc
end_loop_below_ascending_pc:
            pop RBX
        ret

#-----------------------------------
.globl print_above_descending
.type print_above_descending, @function
#-----------------------------------
print_above_descending:
            push RBX

# The loop counter starts above the end of the section

            lea RBX, QWORD PTR [RIP+array_end+2]
loop_back_above_descending:
            sub RBX,4
            cmp RBX, offset array
            jb end_loop_above_descending
            movsx EDX,WORD PTR [RBX]
            lea RSI,QWORD PTR [RIP+format]
            xor EAX,EAX
            mov EDI,1
            call __printf_chk@PLT
            jmp loop_back_above_descending
end_loop_above_descending:
            pop RBX
            ret



.section .rodata ,"a",@progbits

format_one:
          .string "single element %i\n"
format:
          .string "%i\n"
msg1:
          .string "Printing data"
msg2:
          .string "Printing descending"

.data

.globl array
.type array, @object
array:
          .byte 0xa
          .byte 0x0
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

.section .data2 ,"aw",@progbits

.globl array_data2
.type array_data2, @object
array_data2:
          .byte 0xa
          .byte 0x0
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
array_end_data2:

#===================================
.bss
#===================================

.align 16
          .zero 16
