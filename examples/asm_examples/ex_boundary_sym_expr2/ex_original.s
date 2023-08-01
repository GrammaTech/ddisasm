.intel_syntax noprefix
.text

.type foo, @function
foo:
    push RBX
    push RCX
    mov RCX,QWORD PTR [RDI]
    mov RBX, RDI
    add RBX, 8
    mov RBX,QWORD PTR [RBX]
beg_loop:
    cmp RBX,RCX
    jbe end_loop
    sub RBX,8
    mov RDX,QWORD PTR [RBX]
    lea RSI,QWORD PTR [RIP+format_string]
    xor EAX,EAX
    mov EDI,1
    push RCX
    call __printf_chk@PLT
    pop RCX
    jmp beg_loop
end_loop:
    pop RCX
    pop RBX
    xor EAX,EAX
    ret

#-----------------------------------
.globl main
.type main, @function
#-----------------------------------
main:
    push RBX
    mov RDI,OFFSET .L0
    call foo
    pop RBX
    xor EAX,EAX
    ret

#===================================
.section .rodata ,"a",@progbits
#===================================

format_string: .string "N=%s\n"
str1: .string "string.1"
str2: .string "string.2"
str3: .string "string.3"
str4: .string "string.4"

#===================================
# end section .rodata
#===================================

#===================================
.data
#===================================
.L0:
    .quad addr_array_start
    .quad addr_array_end
addr_array_start:
    .quad str1
    .quad str2
    .quad str3
    .quad str4
addr_array_end:
#===================================
# end section .data
#===================================
# .eh_frame_hdr is placed right after .data (see the linker-script.ld)
