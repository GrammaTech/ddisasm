
.intel_syntax noprefix
.extern printf
.extern exit

.section .rodata
msg_main1:
  .string "main: calling conditional_sinkcall(5)\n"
msg_main2:
  .string "main: calling conditional_sinkcall(2)\n"
msg_main3:
  .string "main: calling conditional_sinkcall(0) -- should not return\n"
msg_after:
  .string "main: AFTER conditional_sinkcall(0) (unreachable)\n"

msg_conditional_sinkcall_enter:
  .string "conditional_sinkcall: entered with x=%d\n"
msg_conditional_sinkcall_ret:
  .string "conditional_sinkcall: returning normally\n"
msg_fatal:
  .string "fatal_error: exiting program\n"

.section .text

# ---------------------------------------
# void fatal_error()
# prints message then exits (noreturn)
# ---------------------------------------
.type fatal_error,@function
fatal_error:
    lea rdi, msg_fatal[rip]
    xor eax, eax
    call printf

    xor edi, edi
    call exit

    # unreachable safeguard
    hlt


# ---------------------------------------
# void conditional_sinkcall(int x)
# argument in edi
# ---------------------------------------
.type conditional_sinkcall,@function
conditional_sinkcall:
    push rbp
    mov rbp, rsp
    sub rsp, 16

    mov [rbp-4], edi # save argument x

    # log entry
    mov esi, edi
    lea rdi, msg_conditional_sinkcall_enter[rip]
    xor eax, eax
    call printf

    mov edi, [rbp-4] # restore x
    test edi, edi
    je .error_path

    lea rdi, msg_conditional_sinkcall_ret[rip]
    xor eax, eax
    call printf

    leave
    ret

.error_path:
    leave
    call fatal_error # no return
    hlt


# ---------------------------------------
# main()
# ---------------------------------------
.global main
.type main,@function
main:
    push rbp
    mov rbp, rsp
    sub rsp, 16

    lea rdi, msg_main1[rip]
    xor eax, eax
    call printf

call_1:
    mov edi, 5
    call conditional_sinkcall

    lea rdi, msg_main2[rip]
    xor eax, eax
    call printf

call_2:
    mov edi, 2
    call conditional_sinkcall

    nop
    nop
    nop
    nop

    lea rdi, msg_main3[rip]
    xor eax, eax
    call printf

    mov edi, 0
    # 0: sink call: does not return
    call conditional_sinkcall

    nop
    nop
    nop

.type fall_through_func,@function
fall_through_func:
    # unreachable if analysis works
    lea rdi, msg_after[rip]
    xor eax, eax
    call printf

    xor edi, edi
    call exit
