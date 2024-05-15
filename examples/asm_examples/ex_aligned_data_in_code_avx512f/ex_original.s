# This example is to demonostrate that data-in-code is properly aligned
# when it is referenced by instructions that require explicitly aligned memory.
# If not properly aligned, it may cause a segmentation fault due to alignment
# requirement violation.
# See Table 15-6 in https://cdrdv2.intel.com/v1/dl/getContent/671200.
#
# This example tests avx512 instructions.

    .section .text

.globl main
.type main, @function
main:
    call print_message1

    # Load data into ZMM register using movdqa: `data512` needs to be aligned.
    vmovaps data512(%rip), %zmm0

    # Load data into ZMM register using vmovups: `data512u` does not need to be aligned.
    vmovups data512u(%rip), %zmm1

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

.align 64
data512:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

    .zero 3
data512u:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

    .section .data

message1:
    .ascii "Performing SIMD operations...\n"
    .byte 0
message2:
    .ascii "SIMD operations completed.\n"
    .byte 0
