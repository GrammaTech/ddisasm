.intel_syntax noprefix


.globl foo
.align 16
.type foo, @function
foo:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
    push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
    mov RBP,RSP
    pop RBP
.cfi_def_cfa 7, 8
    ret
# some NOPs
    nop
    nop
    nop
# multiple cfi directives at the end
.cfi_remember_state
.cfi_restore_state
.cfi_endproc


# Misalign FDE frame
# This mimics `RESTORE` in sysdeps/unix/sysv/linux/x86_64/sigaction.c.
    nop
.align 16
.LSTART_bar:
    .type bar, @function
bar:
    mov RAX,15
    syscall
.LEND_bar:
.section .eh_frame,"a",@progbits
.LSTARTFRAME_bar:
    .long .LENDCIE_bar-.LSTARTCIE_bar
.LSTARTCIE_bar:
    .long 0
    .byte 1
    .string "zRS"
    .uleb128 1
    .sleb128 -8
    .uleb128 16
    .uleb128 .LENDAUGMNT_bar-.LSTARTAUGMNT_bar
.LSTARTAUGMNT_bar:
    .byte 0x1b
.LENDAUGMNT_bar:
    .align 8
.LENDCIE_bar:
    .long .LENDFDE_bar-.LSTARTFDE_bar
.LSTARTFDE_bar:
    .long .LSTARTFDE_bar-.LSTARTFRAME_bar
    # `LSTART_' is subtracted 1 as debuggers assume a `call' here.
    .long (.LSTART_bar-1)-.
    .long .LEND_bar-(.LSTART_bar-1)
    .uleb128 0

    # skip...

    .align 8
.LENDFDE_bar:
    .previous

.globl main
.align 16
.type main, @function
main:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
    push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
    mov RBP,RSP
    call foo
    lea RAX, [rip+bar]
    pop RBP
.cfi_def_cfa 7, 8
    ret
.cfi_endproc
