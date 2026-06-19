/*
 * Regression test for symbol selection when multiple symbols share the same
 * function address.
 */
    # --------------------------------------
    .section .text
    .globl main
    .type main, @function
main:
    pushq  %rbp
    movq   %rsp, %rbp

    call   _foo # direct call to _foo to make sure _foo to be marked as code
    call   print_symbols

    xorl   %eax, %eax
    leave
    ret

    .type print_symbols, @function
    .align 2
print_symbols:
    pushq  %r14
    subq   $8, %rsp

    leaq   _xref_block+8(%rip), %r14
    movq   (%r14), %r14
    movq   (%r14), %rsi
    movq   $7, %rdx
    leaq   fmt_str(%rip), %rdi
    xorl   %eax, %eax
    call   printf@PLT

    addq   $8, %rsp
    popq   %r14
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

    .globl _xref_block
    .type  _xref_block, @object
_xref_block:
    .quad 0
    .quad __start_xref_array
    .quad __stop_xref_array

    # --------------------------------------
    .section xref_array,"a",@progbits
    .align 8

    .quad str.1
    .quad str.2
    .quad str.3
.xref_array_end:

# At these address, the following three symbols share the same address:
# __stop_xref_array: linker-generated symbol
# .xref_array_end: user-defined symbol
# _foo
#
# The aux_data `FunctionNames` should select `_foo` over the other two symbols.
# If either of the other two symbols is incorrectly chosen aa the function name,
# the generated assembly may contain an invalid .size directive. For example:
#_foo:
#    xorl %eax,%eax
#    retq
#.size .xref_array_end, . - .xref_array_end
#
# Since `.xref_array_end` is not the function symbol, the assembler rejects
# the directive with:
#
# Error: .size expression for .xref_array_end does not evaluate to a constant

    # --------------------------------------
    .section extra_text,"ax",@progbits
    .align 8
    .globl _foo
    .type _foo, @function
_foo:
    xorl %eax, %eax
    ret
