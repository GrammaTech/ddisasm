#------------------------------------------------------------------------------
# Test that no symbolic expression is derived at the imm32 field of valid_instr
# due to a non-code overlapping instruction (overlap_instr) whose disp32 field
# is at the same address. See valid_instr below for the full byte layout.
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
# valid_instr is a 12-byte instruction whose final 4 bytes encode an immediate,
# non-TLS operand. The final 8 bytes of valid_instr happen to encode an 8-byte
# overlapping instruction (overlap_instr) whose final 4 bytes encode a
# TLS-relative operand at the same address as valid_instr's immediate field.
# Since overlap_instr is not code, no symbolic expression should be derived
# at that shared address.
#
#   +0  +1  +2  +3 | +4   +5   +6   +7 | +8   +9   +10  +11
#   48  81  BC  25 | 64   8B   04   25 | F8   FF   FF   FF
#   valid_instr (cmpq $-8, 0x25048b64(%rbp,%riz,1))
#                  ^--- overlap_instr (mov %fs:-8, %eax) --^
#                                      ^--- shared bytes --^
# -----------------------------------------------------------------------------
valid_instr:
    .byte 0x48, 0x81, 0xBC, 0x25 # cmpq r/m64, imm32  REX+opc+ModRM+SIB
    .byte 0x64, 0x8B, 0x04, 0x25 # disp32=0x25048B64
                                 # (also: first 4 bytes of overlap_instr)
    .byte 0xF8, 0xFF, 0xFF, 0xFF # imm32=-8 (shared with overlap_instr disp32)

.Lcode:
    xor %eax, %eax
    ret
