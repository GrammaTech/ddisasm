# This example test negative heuristics for symbolic operands

.intel_syntax noprefix

.text
.global main
main:
# These should be symbolized

rip_lea:
    lea rdi, qword ptr [rip+message]
    call puts@plt
rip_lea_misleading:
    lea rdx, qword ptr [rip+message]
    imul rdx, 3
rip_lea_misleading_call_rdi:
    lea rdi, qword ptr [rip+message]
    call aux_fun
    imul rdi, 3
rip_lea_misleading_call_rdx:
    lea rdx, qword ptr [rip+message]
    call aux_fun_rdx
    imul rdx, 3

# These should NOT be symbolized
# We use "message" in the original to ensure it looks like an address

mov_immediate:
    # 0x712300 + 0x10 + 974064 = 0x800000
    # NOTE: 0x10 accounts for two extra 8-byte variables inserted at the
    #       beginning of the .data section by the linker.
    mov rdi, OFFSET message+974064
    call aux_fun_print_imm
    imul rdi, 3
print_peer:
    lea rdi, qword ptr [rip+str_peer]
    call aux_fun
    imul rdi, 3
lea_multiplied:
    lea rax, qword ptr [rax+message]
    imul rax, 3
lea_cmp:
    lea rax, qword ptr [rax+message]
    cmp rax, 3
    mov rax, 0
    ret

aux_fun:
    call puts@plt
    ret

# Functions can return small structs
# in RAX+RDX in linux
aux_fun_rdx:
    mov rdi, rdx
    call puts@plt
    mov rax, 0
    mov rdx, 0
    ret

aux_fun_print_imm:
    mov rsi, rdi
    lea rdi, qword ptr [rip+fmt_str]
    xor eax, eax
    call printf@plt
    ret

# This section is pinned at 0x712300 (see link.dl).
.data
message:
    .asciz "Hello"

fmt_str:
    .asciz "Hello: 0x%x\n"

.align 8
# 0x712328
    .quad .L_726560
numeric_data:
# This is numeric and should NOT be symbolized as .L_800000.
    .byte 0x00  # 0x800000
    .byte 0x00
    .byte 0x80
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
str_peer:
# This is a string and should NOT be symbolized as .L_726565 or .L_726560+5.
    .byte 0x70 # .string "peer"
    .quad .L_726560+5
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
# 0x712350
    .zero 82448
# 0x726560
.L_726560:
    .byte 0x77
    .zero 0x100

.align 8
    .quad str_peer

dummy:
    .fill 0x100000, 1, 0
