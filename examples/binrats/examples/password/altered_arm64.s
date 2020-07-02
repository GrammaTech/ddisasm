#===================================
#===================================

nop
nop
nop
nop
nop
nop
nop
nop
.L_0:

#===================================
.section .interp ,"a",@progbits
.align 8
#===================================

          .byte 0x2f
          .byte 0x6c
          .byte 0x69
          .byte 0x62
          .byte 0x2f
          .byte 0x6c
          .byte 0x64
          .byte 0x2d
          .byte 0x6c
          .byte 0x69
          .byte 0x6e
          .byte 0x75
          .byte 0x78
          .byte 0x2d
          .byte 0x61
          .byte 0x61
          .byte 0x72
          .byte 0x63
          .byte 0x68
          .byte 0x36
          .byte 0x34
          .byte 0x2e
          .byte 0x73
          .byte 0x6f
          .byte 0x2e
          .byte 0x31
           .zero 1
#===================================

#===================================

#===================================
.text
.align 16
#===================================

# BEGIN - Function Header
#-----------------------------------
.align 4
.globl setup_users
.type setup_users, @function
setup_users:
#-----------------------------------
# END   - Function Header

setup_users:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 31, 0
            stp x29,x30,[sp,#-48]!
.cfi_def_cfa_offset 48
.cfi_offset 29, -48
.cfi_offset 30, -40
            mov x29,sp
            movz x0,#528
            bl malloc

            str x0,[sp,#24]
            ldr x0,[sp,#24]
            add x2,x0,#8
            adrp x0, .L_de0
            add x1,x0, :lo12:.L_de0
            mov x0,x2
            ldr w2,[x1]
            str w2,[x0]
            ldrh w1,[x1,#4]
            strh w1,[x0,#4]
            ldr x0,[sp,#24]
            add x2,x0,#264
            adrp x0, .L_de8
            add x1,x0, :lo12:.L_de8
            mov x0,x2
            ldr x2,[x1]
            str x2,[x0]
            ldr w1,[x1,#8]
            str w1,[x0,#8]
            ldr x0,[sp,#24]
            movz x1,#16960
            movk x1,#15,lsl #16
            str x1,[x0,#520]
            movz x0,#528
            bl malloc

            str x0,[sp,#32]
            ldr x0,[sp,#32]
            add x2,x0,#8
            adrp x0, .L_df8
            add x1,x0, :lo12:.L_df8
            mov x0,x2
            ldr w2,[x1]
            str w2,[x0]
            ldrh w1,[x1,#4]
            strh w1,[x0,#4]
            ldr x0,[sp,#32]
            add x1,x0,#264
            adrp x0, .L_e00
            add x0,x0, :lo12:.L_e00
            mov x2,x1
            mov x3,x0
            ldp x0,x1,[x3]
            stp x0,x1,[x2]
            add x1,x3,#13
            add x0,x2,#13
            ldr x1,[x1]
            str x1,[x0]
            ldr x0,[sp,#32]
            movz x1,#783
            str x1,[x0,#520]
            movz x0,#528
            bl malloc

            str x0,[sp,#40]
            ldr x0,[sp,#40]
            add x2,x0,#8
            adrp x0, .L_e18
            add x1,x0, :lo12:.L_e18
            mov x0,x2
            ldr w2,[x1]
            str w2,[x0]
            ldrh w1,[x1,#4]
            strh w1,[x0,#4]
            ldr x0,[sp,#40]
            add x2,x0,#264
            adrp x0, .L_e20
            add x1,x0, :lo12:.L_e20
            mov x0,x2
            ldr x2,[x1]
            str x2,[x0]
            ldr w1,[x1,#8]
            str w1,[x0,#8]
            ldr x0,[sp,#40]
            movz x1,#2
            str x1,[x0,#520]
            ldr x0,[sp,#24]
            ldr x1,[sp,#32]
            str x1,[x0]
            ldr x0,[sp,#32]
            ldr x1,[sp,#40]
            str x1,[x0]
            ldr x0,[sp,#40]
            str xzr,[x0]
            ldr x0,[sp,#24]
            ldp x29,x30,[sp],#48
.cfi_restore 30
.cfi_restore 29
.cfi_def_cfa_offset 0
            ret
.cfi_endproc
# BEGIN - Function Header
#-----------------------------------
.align 16
.globl print_users
.type print_users, @function
print_users:
#-----------------------------------
# END   - Function Header

print_users:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 31, 0
            stp x29,x30,[sp,#-48]!
.cfi_def_cfa_offset 48
.cfi_offset 29, -48
.cfi_offset 30, -40
            mov x29,sp
            str x0,[sp,#24]
            adrp x0, .L_e30
            add x0,x0, :lo12:.L_e30
            bl puts

            str xzr,[sp,#40]
            b .L_b64

.L_b30:
            ldr x0,[sp,#40]
            add x0,x0,#1
            str x0,[sp,#40]
            ldr x0,[sp,#24]
            add x0,x0,#8
            mov x2,x0
            ldr x1,[sp,#40]
            adrp x0, .L_e40
            add x0,x0, :lo12:.L_e40
            bl printf

            # --- CHANGE ---
            # print out the password of each struct too
            ldr x0,[sp,#24]
            add x0,x0,#8
            add x0,x0,#256
            mov x2,x0
            ldr x1,[sp,#40]
            adrp x0, .L_e40
            add x0,x0, :lo12:.L_e40
            bl printf
            # --- --- ---

            ldr x0,[sp,#24]
            ldr x0,[x0]
            str x0,[sp,#24]

.L_b64:
            ldr x0,[sp,#24]
            cmp x0,#0
            b.ne .L_b30

            movz w0,#10
            bl putchar

            nop
            nop
            nop
            nop
            ldp x29,x30,[sp],#48
.cfi_restore 30
.cfi_restore 29
.cfi_def_cfa_offset 0
            ret
.cfi_endproc
# BEGIN - Function Header
#-----------------------------------
.align 4
.globl getUser
.type getUser, @function
getUser:
#-----------------------------------
# END   - Function Header

getUser:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 31, 0
            stp x29,x30,[sp,#-32]!
.cfi_def_cfa_offset 32
.cfi_offset 29, -32
.cfi_offset 30, -24
            mov x29,sp
            str x0,[sp,#24]
            str x1,[sp,#16]
            b .L_bc4

.L_b98:
            ldr x0,[sp,#24]
            add x0,x0,#8
            ldr x1,[sp,#16]
            bl strcmp

            cmp w0,#0
            b.ne .L_bb8

            ldr x0,[sp,#24]
            b .L_bd4

.L_bb8:
            ldr x0,[sp,#24]
            ldr x0,[x0]
            str x0,[sp,#24]

.L_bc4:
            ldr x0,[sp,#24]
            cmp x0,#0
            b.ne .L_b98

            movz x0,#0

.L_bd4:
            ldp x29,x30,[sp],#32
.cfi_restore 30
.cfi_restore 29
.cfi_def_cfa_offset 0
            ret
.cfi_endproc
# BEGIN - Function Header
#-----------------------------------
.align 4
.globl main
.type main, @function
main:
#-----------------------------------
# END   - Function Header

main:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 31, 0
            sub sp,sp,#560
.cfi_def_cfa_offset 560
            stp x29,x30,[sp]
.cfi_offset 29, -560
.cfi_offset 30, -552
            mov x29,sp
            adrp x0, :got:__stack_chk_guard
            ldr x0,[x0,:got_lo12:__stack_chk_guard]
            ldr x1,[x0]
            str x1,[sp,#552]
            movz x1,#0
            bl setup_users

            str x0,[sp,#24]

            # --- CHANGE ---
            # call the "print_users" function too
            bl print_users
            # ---  ---  ---

            adrp x0, .L_e50
            add x0,x0, :lo12:.L_e50
            bl puts

            adrp x0, .L_e70
            add x0,x0, :lo12:.L_e70
            bl printf

            add x0,sp,#40
            mov x1,x0
            adrp x0, .L_e80
            add x0,x0, :lo12:.L_e80
            bl __isoc99_scanf

            add x0,sp,#40
            mov x1,x0
            ldr x0,[sp,#24]
            bl getUser

            str x0,[sp,#32]
            ldr x0,[sp,#32]
            cmp x0,#0
            b.ne .L_c6c

            add x0,sp,#40
            mov x1,x0
            adrp x0, .L_e88
            add x0,x0, :lo12:.L_e88
            bl printf

            movz w0,#0
            b .L_d0c

.L_c6c:
            adrp x0, .L_ea8
            add x0,x0, :lo12:.L_ea8
            bl printf

            add x0,sp,#296
            mov x1,x0
            adrp x0, .L_e80
            add x0,x0, :lo12:.L_e80
            bl __isoc99_scanf

            ldr x0,[sp,#32]
            add x0,x0,#264
            add x1,sp,#296
            bl strcmp

            cmp w0,#0

            # --- CHANGE ---
            # jump to .L_cb8 label regardless of comparison result
            # - this means that the password check will be bypassed
            b .L_cb8
            # ---  ---  ---

            adrp x0, .L_eb8
            add x0,x0, :lo12:.L_eb8
            bl puts

            movz w0,#0
            b .L_d0c

.L_cb8:
            ldr x0,[sp,#32]
            add x0,x0,#8
            mov x1,x0
            adrp x0, .L_ed8
            add x0,x0, :lo12:.L_ed8
            bl printf

            movz w0,#10
            bl putchar

            ldr x0,[sp,#32]
            add x0,x0,#8
            mov x1,x0
            adrp x0, .L_ef0
            add x0,x0, :lo12:.L_ef0
            bl printf

            # --- CHANGE ---
            # print a new string to the screen
            adrp x0, .L_added
            add x0, x0, :lo12:.L_added
            bl puts
            # ---  ---  ---

            # --- CHANGE ---
            # use the same kind of code as below, slightly altered, to
            # update the balance of the chosen user by 1000
            ldr x0, [sp,#32]
            add x0, x0, #520
            ldr x1, [x0]
            add x1, x1, #1000
            str x1, [x0]
            # ---  ---  ---

            ldr x0,[sp,#32]
            ldr x0,[x0,#520]
            mov x1,x0
            adrp x0, .L_f00
            add x0,x0, :lo12:.L_f00
            bl printf

            movz w0,#0

.L_d0c:
            mov w1,w0
            adrp x0, :got:__stack_chk_guard
            ldr x0,[x0,:got_lo12:__stack_chk_guard]
            ldr x2,[sp,#552]
            ldr x0,[x0]
            eor x0,x2,x0
            cmp x0,#0
            b.eq .L_d30

            bl __stack_chk_fail

.L_d30:
            mov w0,w1
            ldp x29,x30,[sp]
.L_d38:
            add sp,sp,#560
.cfi_restore 29
.cfi_restore 30
.cfi_def_cfa_offset 0
            ret
.cfi_endproc
#===================================

#===================================

#===================================
.section .rodata ,"a",@progbits
.align 8
#===================================

_IO_stdin_used:
          .byte 0x1
           .zero 1
          .byte 0x2
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_de0:
          .string "admin"
           .zero 1
           .zero 1
.L_de8:
          .string "4dm1n__4eva"
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_df8:
          .string "alice"
           .zero 1
           .zero 1
.L_e00:
          .string "!alice12!_veuje@@hak"
           .zero 1
           .zero 1
           .zero 1
.L_e18:
          .string "abdul"
           .zero 1
           .zero 1
.L_e20:
          .string "passw0rd123"
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_e30:
          .string "--- USERS ---"
           .zero 1
           .zero 1
.L_e40:
          .string " %02ld. %s\n"
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_e50:
          .string "Welcome to BigBank Australia!"
           .zero 1
           .zero 1
.L_e70:
          .string "Username: "
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_e80:
          .string "%255s"
           .zero 1
           .zero 1
.L_e88:
          .string "User < %s > does not exist.\n"
           .zero 1
           .zero 1
           .zero 1
.L_ea8:
          .string "Password: "
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_eb8:
          .string "ERROR: incorrect password"
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
.L_ed8:
          .string "Logged in as < %s >!\n"
           .zero 1
           .zero 1
.L_ef0:
          .string "Welcome, %s!\n"
           .zero 1
           .zero 1
.L_f00:
          .string "Your balance: $%ld\n"

# --- CHANGE ---
# add a new string to be able to use
.L_added:
          .string "Adding 1000 to balance...\n"
# ---  ---  ---
#===================================

#===================================
.L_10b4:

#===================================
.section .init_array ,"wa"
#===================================

__init_array_start:
__frame_dummy_init_array_entry:
#===================================

#===================================

#===================================
.section .fini_array ,"wa"
#===================================

__init_array_end:
__do_global_dtors_aux_fini_array_entry:
#===================================

#===================================

#===================================
.data
.align 16
#===================================

__data_start:
data_start:
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
           .zero 1
__dso_handle:
          .quad __dso_handle
#===================================

#===================================

#===================================
.bss
.align 16
#===================================

_edata:
__bss_start:
__bss_start__:
__TMC_END__:
completed.9119:
           .zero 8
__bss_end__:
__end__:
_bss_end__:
_end:
#===================================

#===================================
