#------------------------------------------------------------------------------
# Unit test: overlapping instruction causes tls_relative_operand misattribution
#
# The tls_relative_operand rule fires when it finds:
#   op_indirect(Op, FS, "NONE", "NONE", _, Offset, _), Offset < 0
#
# valid_instr is a CMP with both a disp32 memory operand and an imm32.
# Its imm32 field shares the same address as overlap_instr's disp32 field.
# valid_instr does not use FS.
#
# A TLS variable is declared in .tdata so that tls_segment is populated in
# the disassembly facts, satisfying the tls_segment(_,TlsEnd,Align) condition.
#
# Byte layout:
#
#   valid_instr:   48 81 BC 25 | 64 8B 04 25 | F8 FF FF FF
#                  cmpq $-8, 0x25048b64(%rbp,%riz,1)
#                  opc+mrm+sib  ^disp32(+4)^   ^imm32(+8)^
#                               ^
#                  overlap_instr (= valid_instr+4)
#                               64 8B 04 25 | F8 FF FF FF
#                               mov %fs:-8, %eax
#                               FS NONE NONE  ^disp32(+4)^
#
#   valid_instr.imm_addr    = valid_instr+8
#   overlap_instr.addr      = valid_instr+4
#   overlap_instr.disp_addr = overlap_instr+4 = valid_instr+8  ✓  (shared)
#
# The 0x64 byte in valid_instr's disp32 field is a data byte, not an FS prefix,
# so valid_instr does not use FS.
#
# overlap_instr matches the rule:
#   op_indirect(Op, FS, "NONE", "NONE", _, -8, _)  ✓  Offset < 0  ✓
#
# Expected: overlap_instr is not code, so tls_relative_operand must not fire
#           for it, and symbolic_expr(valid_instr+8, ...) must be suppressed.
#------------------------------------------------------------------------------

    # TLS variable: gives the binary a .tdata section so that
    # tls_segment(_,TlsEnd,Align) is satisfied in the disassembly facts.
    .section .tdata,"awT",@progbits
    .align 4
tls_var:
    .int 0

    .section .text
    .globl main
main:
    # Jump over valid_instr — its memory operand references an arbitrary
    # address and would fault if executed.
    jmp .Lcode

# -----------------------------------------------------------------------------
# valid_instr: cmpq $-8, 0x25048b64(%rbp,%riz,1)
#   Encoding: 48 81 BC 25 <disp32> <imm32>  (12 bytes, no FS)
#     48       REX.W
#     81       CMP r/m64, imm32 (sign-extended)
#     BC       ModRM: mod=10 (disp32), reg=7 (cmp), rm=100 (SIB)
#     25       SIB: scale=00, index=100 (riz/none), base=101 (rbp)
#     <disp32> 4 bytes at offset +4  (value = 0x25048B64)
#     <imm32>  4 bytes at offset +8  (value = -8)  ← shared with overlap disp32
#
#   The disp32 field (64 8B 04 25) is a plain data value — 0x64 is not
#   decoded as an FS prefix here.
#
#   Byte breakdown:
#   +0  +1  +2  +3 | +4   +5   +6   +7 | +8   +9   +10  +11
#   48  81  BC  25 | 64   8B   04   25 | F8   FF   FF   FF
#   REX+opc+mrm+sib  ^--- disp32 ---^    ^--- imm32 ---^
#                    ^--- overlap_instr starts here (+4)
#                                        ^--- shared addr
#                                             (valid_instr+8 = overlap_instr+4)
# -----------------------------------------------------------------------------
valid_instr:
    .byte 0x48, 0x81, 0xBC, 0x25 # cmpq r/m64, imm32  REX+opc+ModRM+SIB
    .byte 0x64, 0x8B, 0x04, 0x25 # disp32=0x25048B64
                                 # (also: first 4 bytes of overlap_instr)
    .byte 0xF8, 0xFF, 0xFF, 0xFF # imm32=-8 (shared with overlap_instr disp32)

# overlap_instr is NOT emitted — it spans valid_instr[+4 .. +11].
# Decoded from valid_instr+4:
#   64 8B 04 25 F8 FF FF FF   mov %fs:-8, %eax
#   op_indirect: Seg=FS, Base=NONE, Index=NONE, Offset=-8
#                <-- matches tls_relative_operand

.Lcode:
    xor %eax, %eax
    ret
