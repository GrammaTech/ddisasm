.section .text

#-----------------------------------
.type foo, @function
foo:

.cfi_startproc
.cfi_lsda 27, .L_call_site_start
    endbr64
    pushq %rbp
    movq %rsp,%rbp
    nop
    popq %rbp
    retq
.cfi_endproc

# Entry point
.globl main
.type main, @function
main:
    call callThrower    # Call a function that may "throw" an exception
    mov $60, %rax       # syscall: exit
    xor %rdi, %rdi      # status: 0
    syscall

# Dummy function simulating an exception thrower
.type callThrower, @function
callThrower:
    ret                 # Simply return (replace with an actual throw in C++)

# Exception Handling Table
.section .gcc_except_table, "a", @progbits
.align 4

.L_entry_start:
    .byte 0x1           # Entry indicating an exception
    .byte 0x0
    .byte 0x0
    .byte 0x7d
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0

.L_call_site_start:
    .byte 0xff          # Start of a call site
    .byte 0xff          # Additional indicator byte
    .byte 0x1           # Additional indicator byte
    #
    # With this example, if a boundary_sym_expr is not correctly created
    # for symbol_minus_symbol (either the first or the second symbol, or
    # both) or an END symbol is not chosen for such a symbol,
    # the assembler will fail with an error, such as
    #
    # "Error: invalid operands (.note.gnu.property and .gcc_except_table
    # sections) for '-'"
    #
    .uleb128 .L_end - .L_end  # Zero-length entry at the very end of the table
.L_end:
