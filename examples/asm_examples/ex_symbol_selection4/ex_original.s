/*
 * Regression test for symbol selection when multiple symbols share the same
 * function address.
 *
 */
# --------------------------------------
# ==============================================================================
# .text
# ==============================================================================

    .section .text,"ax",@progbits
    .align 8
    .globl main
    .type main, @function
main:
    pushq  %rbp
    movq   %rsp, %rbp
    pushq  %r12
    call   print_symbols
    xorl   %eax, %eax
    popq   %r12
    leave
    ret

    .type print_symbols, @function
    .align 2
print_symbols:
    pushq  %rbp
    movq   %rsp, %rbp
    subq   $16, %rsp
    movl   $7, %esi
    leaq   .L1(%rip), %rdi
    xorl   %eax, %eax
    call   printf@PLT
    call   foo
    leave
    ret

# ==============================================================================
# extra_text1
# ==============================================================================
    .section extra_text1,"ax",@progbits
    .align 8
    .globl foo
    .type foo, @function
foo:
    xorl %eax, %eax
    ret
    .align 8

# ==============================================================================
# extra_text2
# ==============================================================================
    .section extra_text2,"ax",@progbits
    .align 8
    .globl _bar
    .type _bar, @function
_bar:
.LFB_bar:
    .cfi_startproc
    .cfi_personality 0x9b, DW.ref.__gxx_personality_v0
    .cfi_lsda 0x1b, .LLSDA_bar
    pushq  %rbp
    movq   %rsp, %rbp
    subq   $16, %rsp
    movl   %edi, -4(%rbp)

.LEHB0_bar:
    movl   -4(%rbp), %edi
    call   foo
.LEHE0_bar:

    movl   -4(%rbp), %eax
    addl   %eax, %eax
    jmp    .L_bar_ret

.L_handler_bar:
    movl   $-1, %eax

.LEHB1_bar:
    call   __cxa_end_catch@PLT
.LEHE1_bar:

.L_bar_ret:
    leave
    ret
    .cfi_endproc
.LFE_bar:
    .size _bar, .-_bar

    .section .rodata
    .align 8
.L1:
    .string "Hello World! %d\n"
    .zero 16

# ==============================================================================
# .gcc_except_table
# ==============================================================================
    .section .gcc_except_table,"a",@progbits
    .align 4

.LLSDA_bar:
    .byte  0xff
    .byte  0xff
    .byte  0x01
    .uleb128 .LLSDACSE_bar - .LLSDACSB_bar

.LLSDACSB_bar:
    # record 0: guarded call → handler
    .uleb128 .LEHB0_bar     - .LFB_bar
    .uleb128 .LEHE0_bar     - .LEHB0_bar
    .uleb128 .L_handler_bar - .LEHE0_bar
    .uleb128 0
    # The next ULEB128 value becomes the cs_start field of record 1
    # (zero = func start, zero-len, no handler)
    # The symbol `_bar` shares the same address with the END symbol of the
    # preceding section (e.g., `.L_4011f0_END` from `extra_text1`).
    # The `symbol_minus_symbol` rule must prefer `bar` over the aliased END
    # symbol. Otherwise the expression may be emitted using the semantically
    # wrong symbol.
CHECK_SYMBOL:
    .uleb128 _bar-_bar

    # record 1: no-op (zero start, zero len, no lp, no action)
    .uleb128 0
    .uleb128 0
    .uleb128 0

    # record 2: cleanup region → no handler
    .uleb128 .LEHB1_bar     - .LFB_bar
    .uleb128 .LEHE1_bar     - .LEHB1_bar
    .uleb128 0
    .uleb128 0
.LLSDACSE_bar:
    .align 4

    .hidden  DW.ref.__gxx_personality_v0
    .weak    DW.ref.__gxx_personality_v0
    .section .data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
    .align 8
    .type  DW.ref.__gxx_personality_v0, @object
    .size  DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
    .quad  __gxx_personality_v0
