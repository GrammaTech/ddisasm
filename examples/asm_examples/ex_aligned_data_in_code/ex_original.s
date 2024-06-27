# This example is to demonostrate that data-in-code is properly aligned
# when it is referenced by instructions that require explicitly aligned memory.
# If not properly aligned, it may cause a segmentation fault due to alignment
# requirement violation.
# See Table 15-6 in https://cdrdv2.intel.com/v1/dl/getContent/671200.

    .section .text

.globl main
.type main, @function
main:
    call print_message1

    # Load data into XMM register using movdqa: `data128.1` needs to be aligned.
    movdqa data128.1(%rip), %xmm0

    # A pair of instructions forms an access to `data128.2`, which needs to
    # be aligned.
    lea data128.2(%rip), %rax
    movdqa 0(%rax), %xmm1

    # Load data into XMM and YMM using vmovapd: `data256` needs to be 32-bit
    # aligned (YMM) instead of being 16-bit aligned (XMM).
    vmovapd data256(%rip), %xmm0
    vmovapd data256(%rip), %ymm0

    # Load data into YMM register using vmovups: `data256u` does not need to be aligned.
    vmovups data256u(%rip), %ymm1

    call print_message2

    xorq %rax, %rax

    ret

.type print_message1, @function
print_message1:
    lea message1(%rip), %rdi
    call printf
    ret

.align 16
.type print_message2, @function
print_message2:
    lea message2(%rip), %rdi
    call printf
    ret
    .zero 3

.align 16
data128.1:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.2:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 32
data256:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

    .zero 3
data256u:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

    .section .data

message1:
    .ascii "Performing SIMD operations...\n"
    .byte 0
message2:
    .ascii "SIMD operations completed.\n"
    .byte 0
