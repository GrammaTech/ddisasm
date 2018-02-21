/*
Decoding binary
#cmd: ./souffle_disasm  --file ../examples/ex_switch/ex_switch --dir ../examples/ex_switch/dl_files/ --sect .fini --sect .init --sect .plt --sect .text --data_sect .rodata --data_sect .data --data_sect .got.plt --data_sect .plt.got --data_sect .got
Valid binary
Saving sections
Saving symbols
Saving relocations
Decoding section .fini of size 9
Decoding section .init of size 26
Decoding section .plt of size 48
Decoding section .text of size 658
Storing data section .rodata of size 46
Storing data section .data of size 16
Storing data section .got.plt of size 40
Storing data section .plt.got of size 8
Storing data section .got of size 8
Saving results in directory: ../examples/ex_switch/dl_files/
Saving instruction 
Saving data 
Saving invalids 
Saving operators 
Done 
Calling souffle
Collecting results and printing
*/

.intel_syntax noprefix
.globl	main
.type	main, @function
.text 
#----------------------------------- 
.globl one_400526
.type one_400526, @function
one_400526:
#----------------------------------- 
L_400526:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov EDI,  OFFSET L_4006D4 
           call puts 
           mov EAX,  DWORD PTR [RBP-4] 
           leave
           ret

#----------------------------------- 
.globl two_400540
.type two_400540, @function
two_400540:
#----------------------------------- 
L_400540:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov EDI,  OFFSET L_4006D8 
           call puts 
           mov EAX,  DWORD PTR [RBP-4] 
           leave
           ret

#----------------------------------- 
.globl three_40055A
.type three_40055A, @function
three_40055A:
#----------------------------------- 
L_40055A:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov EDI,  OFFSET L_4006DC 
           call puts 
           mov EAX,  DWORD PTR [RBP-4] 
           add EAX,  1 
           leave
           ret

#----------------------------------- 
.globl four_400577
.type four_400577, @function
four_400577:
#----------------------------------- 
L_400577:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov EDI,  OFFSET L_4006E2 
           call puts 
           mov EAX,  DWORD PTR [RBP-4] 
           leave
           ret

#----------------------------------- 
.globl def_400591
.type def_400591, @function
def_400591:
#----------------------------------- 
L_400591:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov EDI,  OFFSET L_4006E7 
           call puts 
           mov EAX,  DWORD PTR [RBP-4] 
           leave
           ret

#----------------------------------- 
.globl fun_4005AB
.type fun_4005AB, @function
fun_4005AB:
#----------------------------------- 
L_4005AB:
           push RBP 
           mov RBP,  RSP 
           sub RSP,  16 
           mov DWORD PTR [RBP-4],  EDI 
           mov DWORD PTR [RBP-8],  ESI 

L_4005B9:
           jmp OFFSET L_400619 

L_4005BB:
           mov EAX,  DWORD PTR [RBP-4] 
           cmp EAX,  2 
           jz OFFSET L_4005E7 
           cmp EAX,  2 
           jg OFFSET L_4005CF 
           cmp EAX,  1 
           jz OFFSET L_4005DB 
           jmp OFFSET L_40060B 

L_4005CF:
           cmp EAX,  3 
           jz OFFSET L_4005F3 
           cmp EAX,  4 
           jz OFFSET L_4005FF 
           jmp OFFSET L_40060B 

L_4005DB:
           mov EAX,  DWORD PTR [RBP-4] 
           mov EDI,  EAX 
           call one_400526 
           jmp OFFSET L_400615 

L_4005E7:
           mov EAX,  DWORD PTR [RBP-4] 
           mov EDI,  EAX 
           call two_400540 
           jmp OFFSET L_400615 

L_4005F3:
           mov EAX,  DWORD PTR [RBP-4] 
           mov EDI,  EAX 
           call three_40055A 
           jmp OFFSET L_400615 

L_4005FF:
           mov EAX,  DWORD PTR [RBP-4] 
           mov EDI,  EAX 
           call four_400577 
           jmp OFFSET L_400615 

L_40060B:
           mov EAX,  DWORD PTR [RBP-4] 
           mov EDI,  EAX 
           call def_400591 

L_400615:
           add DWORD PTR [RBP-4],  1 

L_400619:
           mov EAX,  DWORD PTR [RBP-4] 
           cmp EAX,  DWORD PTR [RBP-8] 
           jl OFFSET L_4005BB 
           nop
           leave
           ret

#----------------------------------- 
.globl main
.type main, @function
main:
#----------------------------------- 
L_400624:
           push RBP 
           mov RBP,  RSP 
           mov EDI,  OFFSET L_4006EC 
           call puts 
           mov ESI,  6 
           mov EDI,  1 
           call fun_4005AB 
           mov EAX,  0 
           pop RBP 
           ret



#=================================== 
.section .rodata
#=================================== 

          .byte 0x1
          .byte 0x0
          .byte 0x2
          .byte 0x0
L_4006D4:
          .string "one"
          .byte 0x0
L_4006D8:
          .string "two"
          .byte 0x0
L_4006DC:
          .string "three"
          .byte 0x0
L_4006E2:
          .string "four"
          .byte 0x0
L_4006E7:
          .string "last"
          .byte 0x0
L_4006EC:
          .string "!!!Hello World!!!"
          .byte 0x0


#=================================== 
.section .data
#=================================== 

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
          .byte 0x0
          .byte 0x0
          .byte 0x0
          .byte 0x0
.bss
L_601038: .zero  7 
L_60103F: .zero  1 


#Result statistics:
 # Number of symbol: 44
 # Number of section: 30
 # Number of instruction: 639
 # Number of op_regdirect: 40
 # Number of op_immediate: 102
 # Number of op_indirect: 84
 # Number of data_byte: 118
 # Number of direct_jump: 39
 # Number of reg_jump: 2
 # Number of indirect_jump: 0
 # Number of pc_relative_jump: 3
 # Number of direct_call: 17
 # Number of reg_call: 1
 # Number of indirect_call: 3
 # Number of pc_relative_call: 0
 # Number of plt_reference: 7
 # Number of likely_ea: 176
 # Number of remaining_ea: 240
 # Number of chunk_overlap: 0
 # Number of function_symbol: 18
 # Number of chunk_start: 36
 # Number of discarded_chunk: 0
 # Number of symbolic_operand: 57
 # Number of labeled_data: 11
 # Number of float_data: 0
 # Number of pointer: 1
 # Number of string: 6
 # Number of bss_data: 2
