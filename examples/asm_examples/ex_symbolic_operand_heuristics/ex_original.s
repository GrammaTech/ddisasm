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

.data
message:
    .asciz "Hello"
