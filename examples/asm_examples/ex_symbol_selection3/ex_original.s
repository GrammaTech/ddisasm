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
 * The linker script places the xref_array section immediately before .bss:
 * xref_array:
 *   ...
 * __stop_xref_array
 *
 * .bss
 *   copy_var (R_X86_64_COPY slot)
 *
 * As a result, `__stop_xref_array` and the copy-relocated instance of
 * `copy_var` resolve to the same address in the final executable.
 *
 * The structure `_xref_block` stores pointers to `__start_xref_array` and
 * `__stop_xref_array`. These symbols define the bounds of the array
 * traversal performed by `print_symbols`.
 *
 *
 * Failure Mode
 * ================
 *
 * Although `__stop_xref_array` and `copy_var` have identical addresses, they
 * represent different symbols with different meanings:
 * - `__stop_xref_array` is a linker-generated section-boundary symbol
 *  identifying the end of `xref_array`.
 * - `copy_var` is a data object.
 *
 * During disassembly and reassembly, ddisasm must preserve the original
 * relocation target. A buggy implementation may incorrectly select `copy_var`
 * instead of `__stop_xref_array` because both symbols are associated with the
 * same address.
 *
 * In a PIE executable, the rewritten binary may therefore emit a relocation
 * against `copy_var` rather than against the intended section-boundary symbol.
 * The resulting pointer no longer represents the logical end of `xref_array`.
 *
 * When `print_symbols` traverses the array using the corrupted bounds, it
 * walks beyond the valid entries and eventually dereferences an invalid
 * address, resulting in a segmentation fault.
 *
 * The dummy reference to `copy_var` in main() exists solely to force creation
 * of the R_X86_64_COPY relocation.
 */
    # --------------------------------------
    .section .text
    .globl main
    .type main, @function
main:
    pushq  %rbp
    movq   %rsp, %rbp
    pushq  %r12

    movq   (copy_var)(%rip), %r12 # dummy reference to copy_var

    call print_symbols

    xorl   %eax, %eax
    popq   %r12
    leave
    ret

    .type print_symbols, @function
    .align 2
print_symbols:
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
    .string "Symbol String: %s\n"

    # --------------------------------------
    .section .data
    .align 8

    .globl _xref_block
    .type  _xref_block, @object
_xref_block:
    .quad 0
    .quad __start_xref_array
    .quad __stop_xref_array
    # `__start_xref_array` and `__stop_xref_array` are linker-generated symbols
    # that mark the beginning and end of the output `xref_array`.
    #
    # The linker script places `xref_array` immediately before .bss, causing
    # `__stop_xref_array` to be co-located with the symbol `copy_var`.
    #
    # If ddisasm incorrectly selects the symbol `code_var` instead of
    # `__stop_xref_array`, `print_symbols` uses the original address in
    # `libfoo.so` instead of the copy-relocated slot in this binary, which
    # causes a seg-fault in the loop iterating the address arrays.

    # --------------------------------------
    .section xref_array,"a",@progbits
    .align 8

    .quad str.1
    .quad str.2
    .quad str.3

    # --------------------------------------
    .section .bss
    .align 8

    .globl dummy
    .type  dummy, @object
    .size  dummy, 64
