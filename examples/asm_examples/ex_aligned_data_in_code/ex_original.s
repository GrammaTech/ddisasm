# This example is to demonostrate that data-in-code is properly aligned.
# Otherwise, it may cause a segmentation fault due to alignment requirement
# violation.

    .section .text

.globl main
.type main, @function
main:
    call print_message1

    # Load data into XMM register using movdqa: `data` needs to be aligned.
    movdqa data(%rip), %xmm0

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

message1:
    .ascii "Performing SIMD operations...\n"
    .byte 0
message2:
    .ascii "SIMD operations completed.\n"
    .byte 0

.align 16
data:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
