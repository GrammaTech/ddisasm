INCLUDELIB libcmt

EXTERN __ImageBase:BYTE
PUBLIC main
EXTRN puts:PROC

.CODE
main:
                SUB   RSP, 40

                mov    R10, 0
                mov    RDX, 1

                LEA    R8,QWORD PTR [__ImageBase]

                ; Offset = (R10 + RDX*2) + RDX
                LEA    RCX,QWORD PTR [R10+RDX*2]
                ADD    RCX,RDX

                ; Base = ImageBase + Offset*2
                LEA    R8,QWORD PTR [R8+RCX*2]

                ; Base + RVA
                LEA    R8,QWORD PTR [R8+(IMAGEREL N_180f32370)]


                MOV    RAX, [R8]
                CMP    RAX, 0CAFEH
                JNE    exit

                LEA    RCX, OFFSET $ok
                CALL   puts

exit:
                ADD   RSP, 40
                RET 0
.DATA
$OK DB	"ok", 00H

N_180f32370     BYTE 0ffH
                BYTE 0ffH
                BYTE 0ffH
                BYTE 0ffH
                BYTE 0ffH
                BYTE 0ffH

cafe:
                BYTE 0feH
                BYTE 0caH
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H
                BYTE 000H
END
