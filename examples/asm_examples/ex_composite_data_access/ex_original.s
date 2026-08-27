# -----------------------------------------------------------------------------
# Regression test for invalid composite_data_access causing spurious alignment.
#
# This reproduces the overlapping-instruction scenario where an invalid decode
# of `lea r12, [rip + target]` — shifted by one byte to
# `lea esp, [rip + target]` at the encoding's second byte — combined with a
# later `movdqa xmm1, [rsp]` can satisfy the `composite_data_access`
# rule and incorrectly introduce a 16-byte alignment requirement at `target`.
#
# `target` is a 1-byte string ("d") deliberately placed mid-section, preceded
# and followed by other data ("abc" before, "e\n" and padding after) so that
# any spurious alignment inserted before `target` would shift its address and
# corrupt the surrounding layout.
#
# The instruction at EA: `lea r12, [rip + target]` (4c8d25df2e0000) has an
# overlapping instruction at EA+1: `lea esp, [rip + target]` (8d25df2e0000).
# The overlapping instruction satisfies composite_data_access via
# the subsequent `movdqa xmm1, [rsp]` read, which makes `target` as alignment-
# required because the AVX instruction requires explicitly aligned memory.
#
# Expected behavior: no alignment should be applied at `target`, and
# disassembly/reprinting should preserve the exact byte layout of the .data
# section. The runtime write(2) call prints "abcde" as a simple end-to-end
# sanity check that the surrounding bytes were not shifted or padded.
# -----------------------------------------------------------------------------

.intel_syntax noprefix

.section .data
    .align 16
    .ascii "abc"        # context before target
target:
    .ascii "d"          # target is itself a 1-byte string object
    .string "e\n"       # more data after target, NUL-terminated

    .align 16
.section .text
.global main
main:
    push rsp
    mov rbp, rsp
    lea r12, [rip + target]
    lea rbp, [rsp + 0x55]

    movdqa xmm1, [rsp]

    # print "abcde" to stdout via write(2), just to prove the layout is sane
    mov rax, 1                  # sys_write
    mov rdi, 1                  # fd = stdout
    lea rsi, [rip + target - 3] # start of "abc..." blob(3 bytes before target)
    mov rdx, 6                  # "abcde\n" = 6 bytes
    syscall

    mov rax, 60                 # sys_exit
    xor rdi, rdi
    syscall

    mov eax, 0
    pop rbp
    ret
