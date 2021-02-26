INCLUDELIB libcmt

EXTERN __ImageBase:BYTE
PUBLIC main
EXTRN puts:PROC

.CODE
main:
                SUB   RSP, 40

                MOV   RAX, 0
                LEA   RDX,[RAX*8+(IMAGEREL N_180f33e70)]
                LEA   RCX,[__ImageBase]
                ADD   RDX,RCX

                MOV   RAX, [RDX]
                CMP   RAX, 48879
                JNE   exit

                LEA   RCX, OFFSET $ok
                CALL  puts

exit:
                ADD   RSP, 40
                RET 0
.DATA
$OK DB	"ok", 00H

N_180f33e70     BYTE 0EFH
                BYTE 0BEH
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H

END
