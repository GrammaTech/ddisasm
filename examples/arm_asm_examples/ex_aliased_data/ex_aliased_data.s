.syntax unified

#===================================
.section .text
#===================================

.arm
.global	main
.type	main, %function
main:
    push { lr }
    cmp r0, #10

    adr r0, .litpool
    ldm r0, {r0, r1, r2}
    ldr r0, .litpool_format

    blt .print

    mvn r0, #0
    pop { pc }

.litpool:
    # This fake code, which ddisasm should (correctly) consider data, create
    # an 8-byte data block at litpool_format. The real code creates a 4-byte
    # data block at litpool_format. ddisasm should be able to differentiate
    # these two data blocks (despite having the same address) and still
    # disassemble code at .print successfully.
    adr r0, .litpool_format
    ldm r0, {r0, r1}

    # ensure this fake code is not considered invalid
    b .print

.litpool_format:
    .long print_format

.print:
    bl printf

    mov r0, #0
    pop { pc }

#===================================
.section .rodata ,"a",%progbits
#===================================
print_format:
    .string "hello world: %x %x\n"
