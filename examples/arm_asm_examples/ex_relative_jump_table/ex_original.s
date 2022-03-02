# ARM
.syntax unified
.arch_extension idiv
.arch_extension sec

#===================================
.section .interp ,"a",%progbits
#===================================

.align 0
          .string "/lib/ld-linux-armhf.so.3"
#===================================
# end section .interp
#===================================

#===================================
.text
#===================================

.align 2
#-----------------------------------
.globl one
.type one, %function
#-----------------------------------
one:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            ldr r3, .L_528
.arm
.L_517:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            ldr r3, [r7, #4]
            mov r0, r3
            adds r7, #8
            mov sp, r7
            pop { r7, pc }
.L_528:
          .long .L_690-.L_517-8
.arm
.align 2
#-----------------------------------
.globl two
.type two, %function
#-----------------------------------
two:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            ldr r3, .L_548
.arm
.L_537:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            ldr r3, [r7, #4]
            mov r0, r3
            adds r7, #8
            mov sp, r7
            pop { r7, pc }
.L_548:
          .long .L_694-.L_537-8
.arm
.align 2
#-----------------------------------
.globl three
.type three, %function
#-----------------------------------
three:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            ldr r3, .L_56c
.arm
.L_557:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            ldr r3, [r7, #4]
            adds r3, #1
            mov r0, r3
            adds r7, #8
            mov sp, r7
            pop { r7, pc }
          .byte 0x0
          .byte 0xbf
.L_56c:
          .long .L_698-.L_557-8
.arm
.align 4
#-----------------------------------
.globl four
.type four, %function
#-----------------------------------
four:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            ldr r3, .L_58c
.arm
.L_57b:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            ldr r3, [r7, #4]
            mov r0, r3
            adds r7, #8
            mov sp, r7
            pop { r7, pc }
.L_58c:
          .long .L_6a0-.L_57b-8
.arm
.align 4
#-----------------------------------
.globl def
.type def, %function
#-----------------------------------
def:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            ldr r3, .L_5ac
.arm
.L_59b:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            ldr r3, [r7, #4]
            mov r0, r3
            adds r7, #8
            mov sp, r7
            pop { r7, pc }
.L_5ac:
          .long .L_6a8-.L_59b-8
.arm
.align 4
#-----------------------------------
.globl fun
.type fun, %function
#-----------------------------------
fun:

            push { r7, lr }
            sub sp, #8
            add r7, sp, #0
            str r0, [r7, #4]
            str r1, [r7]
            b .L_60d
.arm
.align 2
.L_5bd:

            ldr r3, [r7, #4]
            subs r3, #1
            cmp r3, #3
            bhi .L_601
.arm

            adr r2, .L_5d0
            ldr r3, [r2, r3, LSL 2]
            add r2, r3
            bx r2
          .byte 0x0
          .byte 0xbf
          .byte 0x0
          .byte 0x0
.L_5d0:
          .long .L_5e1-.L_5d0
          .long .L_5e9-.L_5d0
          .long .L_5f1-.L_5d0
          .long .L_5f9-.L_5d0
#          .byte 0x0
#          .byte 0x0
.arm
.L_5e1:

            ldr r0, [r7, #4]
            bl one
.arm

            b .L_607
.arm
.L_5e9:

            ldr r0, [r7, #4]
            bl two
.arm

            b .L_607
.arm
.L_5f1:

            ldr r0, [r7, #4]
            bl three
.arm

            b .L_607
.arm
.L_5f9:

            ldr r0, [r7, #4]
            bl four
.arm

            b .L_607
.arm
.align 2
.L_601:

            ldr r0, [r7, #4]
            bl def
.arm
.L_607:

            ldr r3, [r7, #4]
            adds r3, #1
            str r3, [r7, #4]
.arm
.L_60d:

            ldr r2, [r7, #4]
            ldr r3, [r7]
            cmp r2, r3
            blt .L_5bd
.arm

            adds r7, #8
            mov sp, r7
            pop { r7, pc }
.arm
.align 1
#-----------------------------------
.globl main
.type main, %function
#-----------------------------------
main:

            push { r7, lr }
            add r7, sp, #0
            ldr r3, .L_63c
.arm
.L_625:

            add r3, pc
            mov r0, r3
            blx puts
.arm

            movs r1, #6
            movs r0, #1
            bl fun
.arm

            movs r3, #0
            mov r0, r3
            pop { r7, pc }
          .byte 0x0
          .byte 0xbf
.L_63c:
          .long .L_6b0-.L_625-8
#===================================
# end section .text
#===================================

#===================================
.section .rodata ,"a",%progbits
#===================================

.align 2
.L_68c:
          .byte 0x1
          .byte 0x0
          .byte 0x2
          .byte 0x0
.L_690:
          .string "one"
.L_694:
          .string "two"
.L_698:
          .string "three"
          .zero 2
.L_6a0:
          .string "four"
          .zero 3
.L_6a8:
          .string "last"
          .zero 3
.L_6b0:
          .string "!!!Hello World!!!"
#===================================
# end section .rodata
#===================================

#===================================
.data
#===================================

.align 2
#-----------------------------------
.weak data_start
.type data_start, %notype
#-----------------------------------
data_start:
          .zero 4
.L_11004:
          .long .L_11004
#-----------------------------------
.globl _edata
.type _edata, %notype
#-----------------------------------
_edata:
#===================================
# end section .data
#===================================

#===================================
.bss
#===================================

.align 0
completed.11533:
#-----------------------------------
.globl __bss_start__
.type __bss_start__, %notype
#-----------------------------------
__bss_start__:
          .zero 4
.L_1100c:
#-----------------------------------
.globl _end
.type _end, %notype
#-----------------------------------
_end:
#-----------------------------------
.globl _bss_end__
.type _bss_end__, %notype
#-----------------------------------
_bss_end__:
#-----------------------------------
.globl __end__
.type __end__, %notype
#-----------------------------------
__end__:
#-----------------------------------
.globl __bss_end__
.type __bss_end__, %notype
#-----------------------------------
__bss_end__:
#===================================
# end section .bss
#===================================
#-----------------------------------
.weak _ITM_deregisterTMCloneTable
.type _ITM_deregisterTMCloneTable, %notype
#-----------------------------------
#-----------------------------------
.weak _ITM_registerTMCloneTable
.type _ITM_registerTMCloneTable, %notype
#-----------------------------------
#-----------------------------------
.weak __cxa_finalize
.type __cxa_finalize, %function
#-----------------------------------
#-----------------------------------
.weak __gmon_start__
.type __gmon_start__, %notype
#-----------------------------------
#-----------------------------------
.globl __libc_start_main
.type __libc_start_main, %function
#-----------------------------------
#-----------------------------------
.globl abort
.type abort, %function
#-----------------------------------
#-----------------------------------
.globl puts
.type puts, %function
#-----------------------------------
