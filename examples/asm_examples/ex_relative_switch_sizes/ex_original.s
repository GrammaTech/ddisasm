# mark_description "Intel(R) C Intel(R) 64 Compiler for applications running on Intel(R) 64, Version 19.0.5.281 Build 20190815";
# mark_description "-S -O1";
	.file "ex.c"
	.text
..TXTST0:
.L_2__routine_start_main_0:
# -- Begin  main
	.text
# mark_begin;

	.globl main
# --- main()
main:
..B1.1:                         # Preds ..B1.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_main.1:
..L2:
                                                          #149.12
        pushq     %rsi                                          #149.12
	.cfi_def_cfa_offset 16
        xorl      %esi, %esi                                    #149.12
        pushq     $3                                            #149.12
        popq      %rdi                                          #149.12
	# commented call to intel proc
        #call      __intel_new_feature_proc_init                 #149.12
                                # LOE rbx rbp r12 r13 r14 r15
..B1.6:                         # Preds ..B1.1
                                # Execution count [1.00e+00]
        stmxcsr   (%rsp)                                        #149.12
        xorl      %edi, %edi                                    #150.5
        incl      %edi                                          #150.5
        pushq     $6                                            #150.5
        popq      %rsi                                          #150.5
        orl       $32832, (%rsp)                                #149.12
        ldmxcsr   (%rsp)                                        #149.12
..___tag_value_main.4:
#       fun(int, int)
        call      fun                                           #150.5
..___tag_value_main.5:
                                # LOE rbx rbp r12 r13 r14 r15
..B1.2:                         # Preds ..B1.6
                                # Execution count [1.00e+00]
        xorl      %edi, %edi                                    #151.5
        incl      %edi                                          #151.5
        pushq     $6                                            #151.5
        popq      %rsi                                          #151.5
..___tag_value_main.6:
#       fun_wide(int, int)
        call      fun_wide                                      #151.5
..___tag_value_main.7:
                                # LOE rbx rbp r12 r13 r14 r15
..B1.3:                         # Preds ..B1.2
                                # Execution count [1.00e+00]
        xorl      %eax, %eax                                    #152.12
        popq      %rcx                                          #152.12
	.cfi_def_cfa_offset 8
        ret                                                     #152.12
                                # LOE
	.cfi_endproc
# mark_end;
	.type	main,@function
	.size	main,.-main
..LNmain.0:
	.data
# -- End  main
	.text
.L_2__routine_start_fun_1:
# -- Begin  fun
	.text
# mark_begin;

	.globl fun
# --- fun(int, int)
fun:
# parameter 1: %edi
# parameter 2: %esi
..B2.1:                         # Preds ..B2.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_fun.10:
..L11:
                                                         #27.22
        pushq     %r13                                          #27.22
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
        pushq     %r14                                          #27.22
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
        pushq     %r15                                          #27.22
	.cfi_def_cfa_offset 32
	.cfi_offset 15, -32
        movl      %edi, %r14d                                   #27.22
        movl      %esi, %r15d                                   #27.22
        lea       -1(%r14), %r13d                               #27.22
        jmp       ..B2.36       # Prob 100%                     #27.22
                                # LOE rbx rbp r12 r13 r14d r15d
..B2.3:                         # Preds ..B2.36
                                # Execution count [5.00e+00]
        cmpl      $7, %r13d                                     #29.9
        ja        ..B2.21       # Prob 50%                      #29.9
                                # LOE rbx rbp r12 r13 r14d r15d
..B2.4:                         # Preds ..B2.3
                                # Execution count [2.50e+00]
        movzbl    .2.18_2.switchtab.2(%r13), %eax               #29.9
        addq      $..1.6_0.TAG.7.0.6, %rax                      #29.9
        jmp       *%rax                                         #29.9
                                # LOE rbx rbp r12 r13d r14d r15d
..1.6_0.TAG.7.0.6:
..B2.6:                         # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #52.13
        jmp       ..B2.32       # Prob 100%                     #52.13
                                # LOE rbx rbp r12 r13d r14d r15d
..1.6_0.TAG.6.0.6:
..B2.8:                         # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #49.13
        jmp       ..B2.33       # Prob 100%                     #49.13
                                # LOE rbx rbp r12 r13d r14d r15d
..1.6_0.TAG.5.0.6:
..B2.10:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #46.13
        jmp       ..B2.34       # Prob 100%                     #46.13
                                # LOE rbx rbp r12 r13d r14d r15d
..1.6_0.TAG.4.0.6:
..B2.12:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #43.13
        jmp       ..B2.35       # Prob 100%                     #43.13
                                # LOE rbx rbp r12 r13d r14d r15d
..1.6_0.TAG.3.0.6:
..B2.14:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #40.13
                                # LOE rbx rbp r12 r13d r14d r15d
..B2.32:                        # Preds ..B2.6 ..B2.14
                                # Execution count [3.12e-01]
..___tag_value_fun.18:
#       four(int)
        call      four                                          #40.13
..___tag_value_fun.19:
        jmp       ..B2.22       # Prob 100%                     #40.13
                                # LOE
..1.6_0.TAG.2.0.6:
..B2.16:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #37.13
                                # LOE rbx rbp r12 r13d r14d r15d
..B2.33:                        # Preds ..B2.8 ..B2.16
                                # Execution count [3.12e-01]
..___tag_value_fun.20:
#       three(int)
        call      three                                         #37.13
..___tag_value_fun.21:
        jmp       ..B2.22       # Prob 100%                     #37.13
                                # LOE
..1.6_0.TAG.1.0.6:
..B2.18:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #34.13
                                # LOE rbx rbp r12 r13d r14d r15d
..B2.34:                        # Preds ..B2.10 ..B2.18
                                # Execution count [3.12e-01]
..___tag_value_fun.22:
#       two(int)
        call      two                                           #34.13
..___tag_value_fun.23:
        jmp       ..B2.22       # Prob 100%                     #34.13
                                # LOE
..1.6_0.TAG.0.0.6:
..B2.20:                        # Preds ..B2.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #31.13
                                # LOE rbx rbp r12 r13d r14d r15d
..B2.35:                        # Preds ..B2.12 ..B2.20
                                # Execution count [3.12e-01]
..___tag_value_fun.24:
#       one(int)
        call      one                                           #31.13
..___tag_value_fun.25:
        jmp       ..B2.22       # Prob 100%                     #31.13
                                # LOE
..B2.21:                        # Preds ..B2.3
                                # Execution count [2.50e+00]
        movl      %r14d, %edi                                   #55.13
..___tag_value_fun.26:
#       def(int)
        call      def                                           #55.13
..___tag_value_fun.27:
                                # LOE rbx rbp r12 r13 r14d r15d
..B2.22:                        # Preds ..B2.21 ..B2.32 ..B2.33 ..B2.34 ..B2.35
                                #
                                # Execution count [5.00e+00]
        incl      %r14d                                         #58.11
        incl      %r13d                                         #58.11
                                # LOE rbx rbp r12 r13 r14d r15d
..B2.36:                        # Preds ..B2.1 ..B2.22
                                # Execution count [5.00e+00]
        movl      %r13d, %r13d                                  #58.11
        cmpl      %r15d, %r14d                                  #28.13
        jl        ..B2.3        # Prob 82%                      #28.13
                                # LOE
..B2.24:                        # Preds ..B2.36
                                # Execution count [1.00e+00]
        popq      %r15                                          #60.1
	.cfi_def_cfa_offset 24
        popq      %r14                                          #60.1
	.cfi_def_cfa_offset 16
        popq      %r13                                          #60.1
	.cfi_def_cfa_offset 8
        ret                                                     #60.1
                                # LOE
	.cfi_endproc
# mark_end;
	.type	fun,@function
	.size	fun,.-fun
..LNfun.1:
	.section .rodata, "a"
	.align 4
	.align 1
.2.18_2.switchtab.2:
	.byte	..1.6_0.TAG.0.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.1.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.2.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.3.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.4.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.5.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.6.0.6 - ..1.6_0.TAG.7.0.6
	.byte	..1.6_0.TAG.7.0.6 - ..1.6_0.TAG.7.0.6
	.data
# -- End  fun
	.text
.L_2__routine_start_def_2:
# -- Begin  def
	.text
# mark_begin;

	.globl def
# --- def(int)
def:
# parameter 1: %edi
..B3.1:                         # Preds ..B3.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_def.32:
..L33:
                                                         #21.15
        pushq     %r14                                          #21.15
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
        movl      %edi, %r14d                                   #21.15
        movl      $.L_2__STRING.4, %edi                         #22.5
..___tag_value_def.36:
#       puts(const char *)
        call      puts                                          #22.5
..___tag_value_def.37:
                                # LOE rbx rbp r12 r13 r15 r14d
..B3.2:                         # Preds ..B3.1
                                # Execution count [1.00e+00]
        movl      %r14d, %eax                                   #23.12
        popq      %r14                                          #23.12
	.cfi_def_cfa_offset 8
        ret                                                     #23.12
                                # LOE
	.cfi_endproc
# mark_end;
	.type	def,@function
	.size	def,.-def
..LNdef.2:
	.data
# -- End  def
	.text
.L_2__routine_start_fun_wide_3:
# -- Begin  fun_wide
	.text
# mark_begin;

	.globl fun_wide
# --- fun_wide(int, int)
fun_wide:
# parameter 1: %edi
# parameter 2: %esi
..B4.1:                         # Preds ..B4.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_fun_wide.40:
..L41:
                                                         #63.27
        pushq     %r12                                          #63.27
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
        pushq     %r13                                          #63.27
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
        pushq     %r14                                          #63.27
	.cfi_def_cfa_offset 32
	.cfi_offset 14, -32
        pushq     %r15                                          #63.27
	.cfi_def_cfa_offset 40
	.cfi_offset 15, -40
        pushq     %rsi                                          #63.27
	.cfi_def_cfa_offset 48
        movl      %edi, %r14d                                   #63.27
        movl      %esi, %r15d                                   #63.27
        lea       -1(%r14), %r12d                               #63.27
        cmpl      %r15d, %r14d                                  #64.13
        jge       ..B4.76       # Prob 10%                      #64.13
                                # LOE rbx rbp r12 r14d r15d
..B4.2:                         # Preds ..B4.1
                                # Execution count [9.00e-01]
        lea       2(%r15), %r13d                                #89.14
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.3:                         # Preds ..B4.74 ..B4.2
                                # Execution count [5.00e+00]
        cmpl      $7, %r12d                                     #65.9
        ja        ..B4.73       # Prob 50%                      #65.9
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.4:                         # Preds ..B4.3
                                # Execution count [2.50e+00]
        movzwl    .2.20_2.switchtab.2(,%r12,2), %eax            #65.9
        addq      $..1.7_0.TAG.7.0.7, %rax                      #65.9
        jmp       *%rax                                         #65.9
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.7.0.7:
..B4.6:                         # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #133.13
..___tag_value_fun_wide.51:
#       one(int)
        call      one                                           #133.13
..___tag_value_fun_wide.52:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.7:                         # Preds ..B4.6
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #134.6
..___tag_value_fun_wide.53:
#       two(int)
        call      two                                           #134.6
..___tag_value_fun_wide.54:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.8:                         # Preds ..B4.7
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #135.6
..___tag_value_fun_wide.55:
#       three(int)
        call      three                                         #135.6
..___tag_value_fun_wide.56:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.9:                         # Preds ..B4.8
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #136.6
..___tag_value_fun_wide.57:
#       four(int)
        call      four                                          #136.6
..___tag_value_fun_wide.58:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.10:                        # Preds ..B4.9
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #137.6
        jmp       ..B4.92       # Prob 100%                     #137.6
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.6.0.7:
..B4.15:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #123.13
..___tag_value_fun_wide.59:
#       one(int)
        call      one                                           #123.13
..___tag_value_fun_wide.60:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.16:                        # Preds ..B4.15
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #124.6
..___tag_value_fun_wide.61:
#       two(int)
        call      two                                           #124.6
..___tag_value_fun_wide.62:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.17:                        # Preds ..B4.16
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #125.6
..___tag_value_fun_wide.63:
#       three(int)
        call      three                                         #125.6
..___tag_value_fun_wide.64:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.18:                        # Preds ..B4.17
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #126.6
..___tag_value_fun_wide.65:
#       four(int)
        call      four                                          #126.6
..___tag_value_fun_wide.66:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.19:                        # Preds ..B4.18
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #127.6
..___tag_value_fun_wide.67:
#       one(int)
        call      one                                           #127.6
..___tag_value_fun_wide.68:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.20:                        # Preds ..B4.19
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #128.6
..___tag_value_fun_wide.69:
#       two(int)
        call      two                                           #128.6
..___tag_value_fun_wide.70:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.21:                        # Preds ..B4.20
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #129.6
        jmp       ..B4.96       # Prob 100%                     #129.6
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.5.0.7:
..B4.24:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #117.13
        jmp       ..B4.98       # Prob 100%                     #117.13
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.4.0.7:
..B4.29:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #107.13
        jmp       ..B4.91       # Prob 100%                     #107.13
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.3.0.7:
..B4.38:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #97.13
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.91:                        # Preds ..B4.29 ..B4.38
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.71:
#       one(int)
        call      one                                           #97.13
..___tag_value_fun_wide.72:
                                # LOE
..B4.39:                        # Preds ..B4.91
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #98.6
..___tag_value_fun_wide.73:
#       two(int)
        call      two                                           #98.6
..___tag_value_fun_wide.74:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.40:                        # Preds ..B4.39
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #99.6
..___tag_value_fun_wide.75:
#       three(int)
        call      three                                         #99.6
..___tag_value_fun_wide.76:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.41:                        # Preds ..B4.40
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #100.6
..___tag_value_fun_wide.77:
#       four(int)
        call      four                                          #100.6
..___tag_value_fun_wide.78:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.42:                        # Preds ..B4.41
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #101.6
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.92:                        # Preds ..B4.10 ..B4.42
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.79:
#       one(int)
        call      one                                           #101.6
..___tag_value_fun_wide.80:
                                # LOE
..B4.43:                        # Preds ..B4.92
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #102.6
        jmp       ..B4.99       # Prob 100%                     #102.6
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.2.0.7:
..B4.47:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        pushq     $5                                            #87.13
        popq      %rdi                                          #87.13
..___tag_value_fun_wide.81:
#       one(int)
        call      one                                           #87.13
..___tag_value_fun_wide.82:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.48:                        # Preds ..B4.47
                                # Execution count [3.12e-01]
        pushq     $5                                            #88.6
        popq      %rdi                                          #88.6
..___tag_value_fun_wide.83:
#       two(int)
        call      two                                           #88.6
..___tag_value_fun_wide.84:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.49:                        # Preds ..B4.48
                                # Execution count [3.12e-01]
        movl      %r13d, %edi                                   #89.6
..___tag_value_fun_wide.85:
#       three(int)
        call      three                                         #89.6
..___tag_value_fun_wide.86:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.50:                        # Preds ..B4.49
                                # Execution count [3.12e-01]
        pushq     $5                                            #90.6
        popq      %rdi                                          #90.6
..___tag_value_fun_wide.87:
#       four(int)
        call      four                                          #90.6
..___tag_value_fun_wide.88:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.51:                        # Preds ..B4.50
                                # Execution count [3.12e-01]
        pushq     $5                                            #91.6
        popq      %rdi                                          #91.6
..___tag_value_fun_wide.89:
#       one(int)
        call      one                                           #91.6
..___tag_value_fun_wide.90:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.52:                        # Preds ..B4.51
                                # Execution count [3.12e-01]
        pushq     $5                                            #92.6
        popq      %rdi                                          #92.6
..___tag_value_fun_wide.91:
#       two(int)
        call      two                                           #92.6
..___tag_value_fun_wide.92:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.53:                        # Preds ..B4.52
                                # Execution count [3.12e-01]
        movl      %r13d, %edi                                   #93.6
..___tag_value_fun_wide.93:
#       three(int)
        call      three                                         #93.6
..___tag_value_fun_wide.94:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.54:                        # Preds ..B4.53
                                # Execution count [3.12e-01]
        pushq     $5                                            #94.6
        popq      %rdi                                          #94.6
        jmp       ..B4.100      # Prob 100%                     #94.6
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.1.0.7:
..B4.56:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #77.13
..___tag_value_fun_wide.95:
#       one(int)
        call      one                                           #77.13
..___tag_value_fun_wide.96:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.57:                        # Preds ..B4.56
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #78.6
..___tag_value_fun_wide.97:
#       two(int)
        call      two                                           #78.6
..___tag_value_fun_wide.98:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.58:                        # Preds ..B4.57
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #79.6
..___tag_value_fun_wide.99:
#       three(int)
        call      three                                         #79.6
..___tag_value_fun_wide.100:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.59:                        # Preds ..B4.58
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #80.6
..___tag_value_fun_wide.101:
#       four(int)
        call      four                                          #80.6
..___tag_value_fun_wide.102:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.60:                        # Preds ..B4.59
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #81.6
..___tag_value_fun_wide.103:
#       one(int)
        call      one                                           #81.6
..___tag_value_fun_wide.104:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.61:                        # Preds ..B4.60
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #82.6
..___tag_value_fun_wide.105:
#       two(int)
        call      two                                           #82.6
..___tag_value_fun_wide.106:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.62:                        # Preds ..B4.61
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #83.6
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.96:                        # Preds ..B4.21 ..B4.62
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.107:
#       three(int)
        call      three                                         #83.6
..___tag_value_fun_wide.108:
                                # LOE
..B4.63:                        # Preds ..B4.96
                                # Execution count [3.12e-01]
        movl      %r15d, %edi                                   #84.6
        jmp       ..B4.100      # Prob 100%                     #84.6
                                # LOE rbx rbp r12d r13d r14d r15d
..1.7_0.TAG.0.0.7:
..B4.65:                        # Preds ..B4.4
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #67.13
..___tag_value_fun_wide.109:
#       one(int)
        call      one                                           #67.13
..___tag_value_fun_wide.110:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.66:                        # Preds ..B4.65
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #68.6
..___tag_value_fun_wide.111:
#       two(int)
        call      two                                           #68.6
..___tag_value_fun_wide.112:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.67:                        # Preds ..B4.66
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #69.6
..___tag_value_fun_wide.113:
#       three(int)
        call      three                                         #69.6
..___tag_value_fun_wide.114:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.68:                        # Preds ..B4.67
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #70.6
..___tag_value_fun_wide.115:
#       four(int)
        call      four                                          #70.6
..___tag_value_fun_wide.116:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.69:                        # Preds ..B4.68
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #71.6
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.98:                        # Preds ..B4.24 ..B4.69
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.117:
#       one(int)
        call      one                                           #71.6
..___tag_value_fun_wide.118:
                                # LOE
..B4.70:                        # Preds ..B4.98
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #72.6
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.99:                        # Preds ..B4.43 ..B4.70
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.119:
#       two(int)
        call      two                                           #72.6
..___tag_value_fun_wide.120:
                                # LOE
..B4.71:                        # Preds ..B4.99
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #73.6
..___tag_value_fun_wide.121:
#       three(int)
        call      three                                         #73.6
..___tag_value_fun_wide.122:
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.72:                        # Preds ..B4.71
                                # Execution count [3.12e-01]
        movl      %r14d, %edi                                   #74.6
                                # LOE rbx rbp r12d r13d r14d r15d
..B4.100:                       # Preds ..B4.54 ..B4.63 ..B4.72
                                # Execution count [3.12e-01]
..___tag_value_fun_wide.123:
#       four(int)
        call      four                                          #74.6
..___tag_value_fun_wide.124:
        jmp       ..B4.74       # Prob 100%                     #74.6
                                # LOE
..B4.73:                        # Preds ..B4.3
                                # Execution count [2.50e+00]
        movl      %r14d, %edi                                   #143.13
..___tag_value_fun_wide.125:
#       def(int)
        call      def                                           #143.13
..___tag_value_fun_wide.126:
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.74:                        # Preds ..B4.73 ..B4.100
                                # Execution count [5.00e+00]
        incl      %r14d                                         #146.11
        incl      %r12d                                         #146.11
        cmpl      %r15d, %r14d                                  #64.13
        jl        ..B4.3        # Prob 82%                      #64.13
                                # LOE rbx rbp r12 r13d r14d r15d
..B4.76:                        # Preds ..B4.74 ..B4.1
                                # Execution count [1.00e+00]
        popq      %rcx                                          #148.1
	.cfi_def_cfa_offset 40
        popq      %r15                                          #148.1
	.cfi_def_cfa_offset 32
        popq      %r14                                          #148.1
	.cfi_def_cfa_offset 24
        popq      %r13                                          #148.1
	.cfi_def_cfa_offset 16
        popq      %r12                                          #148.1
	.cfi_def_cfa_offset 8
        ret                                                     #148.1
                                # LOE
	.cfi_endproc
# mark_end;
	.type	fun_wide,@function
	.size	fun_wide,.-fun_wide
..LNfun_wide.3:
	.section .rodata, "a"
	.align 2
.2.20_2.switchtab.2:
	.word	..1.7_0.TAG.0.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.1.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.2.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.3.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.4.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.5.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.6.0.7 - ..1.7_0.TAG.7.0.7
	.word	..1.7_0.TAG.7.0.7 - ..1.7_0.TAG.7.0.7
	.data
# -- End  fun_wide
	.text
.L_2__routine_start_one_4:
# -- Begin  one
	.text
# mark_begin;

	.globl one
# --- one(int)
one:
# parameter 1: %edi
..B5.1:                         # Preds ..B5.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_one.133:
..L134:
                                                        #4.15
        pushq     %r14                                          #4.15
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
        movl      %edi, %r14d                                   #4.15
        movl      $.L_2__STRING.0, %edi                         #5.5
..___tag_value_one.137:
#       puts(const char *)
        call      puts                                          #5.5
..___tag_value_one.138:
                                # LOE rbx rbp r12 r13 r15 r14d
..B5.2:                         # Preds ..B5.1
                                # Execution count [1.00e+00]
        movl      %r14d, %eax                                   #6.12
        popq      %r14                                          #6.12
	.cfi_def_cfa_offset 8
        ret                                                     #6.12
                                # LOE
	.cfi_endproc
# mark_end;
	.type	one,@function
	.size	one,.-one
..LNone.4:
	.data
# -- End  one
	.text
.L_2__routine_start_two_5:
# -- Begin  two
	.text
# mark_begin;

	.globl two
# --- two(int)
two:
# parameter 1: %edi
..B6.1:                         # Preds ..B6.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_two.141:
..L142:
                                                        #9.15
        pushq     %r14                                          #9.15
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
        movl      %edi, %r14d                                   #9.15
        movl      $.L_2__STRING.1, %edi                         #10.5
..___tag_value_two.145:
#       puts(const char *)
        call      puts                                          #10.5
..___tag_value_two.146:
                                # LOE rbx rbp r12 r13 r15 r14d
..B6.2:                         # Preds ..B6.1
                                # Execution count [1.00e+00]
        movl      %r14d, %eax                                   #11.12
        popq      %r14                                          #11.12
	.cfi_def_cfa_offset 8
        ret                                                     #11.12
                                # LOE
	.cfi_endproc
# mark_end;
	.type	two,@function
	.size	two,.-two
..LNtwo.5:
	.data
# -- End  two
	.text
.L_2__routine_start_three_6:
# -- Begin  three
	.text
# mark_begin;

	.globl three
# --- three(int)
three:
# parameter 1: %edi
..B7.1:                         # Preds ..B7.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_three.149:
..L150:
                                                        #13.17
        pushq     %r14                                          #13.17
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
        movl      %edi, %r14d                                   #13.17
        movl      $.L_2__STRING.2, %edi                         #14.5
..___tag_value_three.153:
#       puts(const char *)
        call      puts                                          #14.5
..___tag_value_three.154:
                                # LOE rbx rbp r12 r13 r15 r14d
..B7.2:                         # Preds ..B7.1
                                # Execution count [1.00e+00]
        incl      %r14d                                         #15.14
        movl      %r14d, %eax                                   #15.14
        popq      %r14                                          #15.14
	.cfi_def_cfa_offset 8
        ret                                                     #15.14
                                # LOE
	.cfi_endproc
# mark_end;
	.type	three,@function
	.size	three,.-three
..LNthree.6:
	.data
# -- End  three
	.text
.L_2__routine_start_four_7:
# -- Begin  four
	.text
# mark_begin;

	.globl four
# --- four(int)
four:
# parameter 1: %edi
..B8.1:                         # Preds ..B8.0
                                # Execution count [1.00e+00]
	.cfi_startproc
..___tag_value_four.157:
..L158:
                                                        #17.16
        pushq     %r14                                          #17.16
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
        movl      %edi, %r14d                                   #17.16
        movl      $.L_2__STRING.3, %edi                         #18.5
..___tag_value_four.161:
#       puts(const char *)
        call      puts                                          #18.5
..___tag_value_four.162:
                                # LOE rbx rbp r12 r13 r15 r14d
..B8.2:                         # Preds ..B8.1
                                # Execution count [1.00e+00]
        movl      %r14d, %eax                                   #19.12
        popq      %r14                                          #19.12
	.cfi_def_cfa_offset 8
        ret                                                     #19.12
                                # LOE
	.cfi_endproc
# mark_end;
	.type	four,@function
	.size	four,.-four
..LNfour.7:
	.data
# -- End  four
	.section .rodata.str1.4, "aMS",@progbits,1
	.align 4
	.align 4
.L_2__STRING.4:
	.long	1953718636
	.byte	0
	.type	.L_2__STRING.4,@object
	.size	.L_2__STRING.4,5
	.space 3, 0x00 	# pad
	.align 4
.L_2__STRING.0:
	.long	6647407
	.type	.L_2__STRING.0,@object
	.size	.L_2__STRING.0,4
	.align 4
.L_2__STRING.1:
	.long	7305076
	.type	.L_2__STRING.1,@object
	.size	.L_2__STRING.1,4
	.align 4
.L_2__STRING.2:
	.long	1701996660
	.word	101
	.type	.L_2__STRING.2,@object
	.size	.L_2__STRING.2,6
	.space 2, 0x00 	# pad
	.align 4
.L_2__STRING.3:
	.long	1920298854
	.byte	0
	.type	.L_2__STRING.3,@object
	.size	.L_2__STRING.3,5
	.data
	.section .note.GNU-stack, ""
# End
