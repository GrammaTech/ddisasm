# This example shows how ddisasm handles the representation of loop instructions
# and prefixes.

.intel_syntax noprefix

.text
.global main
main:
    mov rcx, 10
    mov rax, 0
countdown:
    add rax, 10
    loop countdown
rep_prefix:
    mov rcx, buffer_end-buffer_begin
    lea rdi, qword ptr [rip+buffer_begin]
    rep stos byte ptr [rdi]
    add al, byte ptr [rip+buffer_end-1]
post_loops:
    # print rax; it should now be 200
    lea rdi, qword ptr [rip+message]
    mov rsi, rax
    mov al, 0
    call printf@plt
    ret

.data
message:
    .asciz "Result: %d\n"
buffer_begin:
    .zero 128
buffer_end:
