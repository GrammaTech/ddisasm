# This example has a variety of jumps and calls

.intel_syntax noprefix

.text
.global main
main:

call_local_direct:
    call fun

call_local_indirect:
    call [fun_ptr]

call_local_indirect_pc:
    call [rip+fun_ptr]

call_local_reg:
    mov rax, qword ptr [fun_ptr]
    call rax

call_local_reg_pc:
    mov rax, qword ptr [rip+fun_ptr]
    call rax

call_local_reg_offset:
    mov rax, offset fun_ptr-8
    add rax, 8
    call [rax]

call_local_reg_offset_pc:
    lea rax, [rip+fun_ptr-8]
    add rax, 8
    call [rax]

call_local_reg_load:
    lea rax, [rip+fun_ptr]
    mov rax, [rax]
    call rax

je_local_direct:
    mov rdi, offset jmp_local_direct
    cmp rdi, rdi
    je jump_target

jmp_local_direct:
    mov rdi, offset jmp_local_indirect
    jmp jump_target

jmp_local_indirect:
    mov rdi, offset jmp_local_reg
    jmp [jump_target_ptr]

jmp_local_reg:
    mov rdi, offset jmp_local_reg_offset
    mov rax, qword ptr [jump_target_ptr]
    cmp rdi, rdi
    jmp rax

jmp_local_reg_offset:
    mov rdi, offset call_ext_reg_printf
    mov rax, offset jump_target_ptr-8
    add rax, 8
    jmp [rax]

# 'printf' does NOT have a plt entry so the register
# and indirect calls get resolved to the external
# address directly

call_ext_reg_printf:
    lea rdi, qword ptr [rip+print_msg]
    mov rsi, 0
    mov rax, 0
    mov rbx, qword ptr [printf_ptr]
    call rbx

call_ext_indirect_printf:
    lea rdi, qword ptr [rip+message]
    mov rsi, 0
    mov rax, 0
    call [printf_ptr]

# Since 'puts' has a plt entry, indirect and reg calls
# will point to the PLT entry

call_ext_reg:
    mov rax, qword ptr [puts_ptr]
    lea rdi, qword ptr [rip+message]
    call rax

call_ext_indirect:
    lea rdi, qword ptr [rip+message]
    call [puts_ptr]

call_ext_plt:
    lea rdi, qword ptr [rip+message]
    call puts@plt

last:
    mov eax, 0
    ret


.global fun
fun:
    lea rdi, qword ptr [rip+message_fun]
    call puts@plt
    mov rax, 0
    ret

.global foo
foo:
    lea rdi, qword ptr [rip+message_fun]
    call puts@plt
    mov rax, 0
    ret


.global jump_target
jump_target:
    jmp rdi

.data
message:
    .asciz "msg\n"
print_msg:
    .asciz "print\n"
message_fun:
    .asciz "msg:fun\n"

puts_ptr:
    .quad puts
fun_ptr:
    .quad fun
jump_target_ptr:
    .quad jump_target
printf_ptr:
    .quad printf
