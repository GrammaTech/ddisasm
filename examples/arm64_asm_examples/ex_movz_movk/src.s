// Test: MOVZ+MOVK address construction in non-PIE ARM64 binaries.
//
// This exercises the movz_movk_pair Datalog rules.  In a non-PIE executable
// the linker fills absolute addresses into the MOVZ/MOVK immediates, so
// ddisasm must recognise the pair as constructing an address and emit
// symbolic operand candidates with G0/G1 attributes.
//
// Expected behaviour after the fix:
//   - ddisasm produces SymAddrConst for both the MOVZ and the MOVK
//   - gtirb-pprinter emits:
//       movz  x0, #:abs_g1:msg
//       movk  x0, #:abs_g0_nc:msg
//   - reassembled binary runs identically.

.arch armv8-a
.file "src.s"

.text
.global main
.type main, %function

main:
    stp     fp, lr, [sp, #-16]!

    // Construct the address of msg using MOVZ + MOVK.
    // The linker/assembler resolves the relocations at link time.
    movz    x0, #:abs_g1:msg
    movk    x0, #:abs_g0_nc:msg

    bl      printf

    mov     x0, #0
    ldp     fp, lr, [sp], #16
    ret

.section .rodata
msg:
    .asciz "Hello from MOVZ+MOVK!\n"
