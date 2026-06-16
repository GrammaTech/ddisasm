/*
 * Regression test for incorrect symbol selection when multiple symbols
 * resolve to the same address.
 *
 * This test uses the linker-generated symbols `__start_xref_array` and
 * `__stop_xref_array` associated with the output section `xref_array`.
 *
 * For an output section named `xref_array`, the linker automatically creates:
 * __start_xref_array marks the beginning of the section and
 * __stop_xref_array marks the first address immediately following the section.
 *
 * Layout
 * ======
 * The linker script places the `xref_array` section immediately before the
 *`extra_data` section:
 * This make `__stop_xref_array` and `_mydata` share the exact same address:
 *
 *   xref_array:
 *   __start_xref_array:
 *     ...
 *   __stop_xref_array:
 *
 * .section extra_data
 *   _mydata:
 *     .quad 0x7
 *
 * The `_xref_block` structure holds pointers to the start and stop symbols of
 * the array. The `print_symbols` function uses these bounds to loop through
 * the data.
 * Even though they share an address, these two symbols mean different things:
 * - `__stop_xref_array`: A linker symbol that marks the end of `xref_array`.
 * - `_mydata`: A standard data object.
 *
 *
 * Failure Mode 1: Array Loop Crash
 * ================================
 *
 * If Ddisasm wrongly picks `_mydata` instead of `__stop_xref_array` for
 * `_xref_block`, the pointer breaks when the section layout changes.
 *
 * If `extra_data` moves before `xref_array`, the loop finishes instantly and
 * print nothing. If it moves after the array, the loop marches past the real
 * data and eventually read an invalid address.
 *
 * Failure Mode 2: Bad Data Output
 * ===============================
 *
 * If Ddisasm wrongly picks `__stop_xref_array` instead `_mydata` for
 * `_mydata_ref`, `print_symbols` will read from the wrong place.
 * It will print garbage data instead of the number 7.
 */
    # --------------------------------------
    .section .text
    .globl main
    .type main, @function
main:
    pushq  %rbp
    movq   %rsp, %rbp
    pushq  %r12

    call print_symbols

    xorl   %eax, %eax
    popq   %r12
    leave
    ret

    .type print_symbols, @function
    .align 2
print_symbols:
    pushq  %r11
    pushq  %r12
    pushq  %r14
    subq   $8, %rsp

    leaq   _xref_block+8(%rip), %r14
    movq   (%r14), %r14 # address of __start_xref_array
    leaq   _xref_block+16(%rip), %r12
    movq   (%r12), %r12 # address of __stop_xref_array
.Lloop_head:
    cmpq  %r12, %r14
    jae   .Lloop_end

    leaq  _mydata_ref(%rip), %r11
    movq  (%r11), %r11
    movq  (%r11), %rdx
    movq  (%r14), %rsi
    leaq  fmt_str(%rip), %rdi
    xorl  %eax, %eax
    call  printf@PLT

    addq $8, %r14
    jmp  .Lloop_head

.Lloop_end:
    addq $8, %rsp
    popq  %r14
    popq  %r12
    popq  %r11
    ret

    # --------------------------------------
    .section .rodata
    .align 8

.L1:
    .string "Hello World! %d\n"
    .zero 16
str.1:
    .string "string1"
str.2:
    .string "string2"
str.3:
    .string "string3"
fmt_str:
    .string "Symbol String: %s: %d\n"

    # --------------------------------------
    .section .data
    .align 8

    .quad 0xDEADBEEF

    .globl _xref_block
    .type  _xref_block, @object
_xref_block:
    .quad 0
    .quad __start_xref_array
    .quad __stop_xref_array
    # `__start_xref_array` and `__stop_xref_array` are linker-generated symbols
    # that mark the beginning and end of the output `xref_array`.
    #
    # The linker script (linker-script.ld) places `xref_array` immediately
    # before `extra_data`, causing `__stop_xref_array` to be co-located with
    # the symbol `_mydata`.
    #
    # Reassemble uses a different linker script (linker-script.reassemble.ld )
    # to change the section layout: it puts `.data` between them.
    #
    # If ddisasm incorrectly selects the symbol `_mydata` instead of
    # `__stop_xref_array`, `print_symbols` will pull an incorrect address from
    # the `extra_data` section, which causes a seg-fault in the loop iterating
    # the address arrays.

_mydata_ref:
    # `_mydata` and `__stop_xref_array` share the same address.
    # If ddisasm incorrectly selects `__stop_xref_array` instead of `_mydata`,
    # `print_symbols` will print garbage data instead of the number 7.
    .quad _mydata

    # --------------------------------------
    .section xref_array,"a",@progbits
    .align 8

    .quad str.1
    .quad str.2
    .quad str.3

    .section extra_data,"aw",@progbits
    .align 8

_mydata:
    .quad 0x7
