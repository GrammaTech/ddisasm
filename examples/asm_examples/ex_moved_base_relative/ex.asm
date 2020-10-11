INCLUDELIB libcmt

EXTERN __ImageBase:BYTE
PUBLIC main
EXTRN puts:PROC

.CODE
main:
               SUB   RSP, 40

               CALL  foo
               MOV   RBX, [RAX]
               CMP   RBX, 070H
               JNE   exit

               CALL  bar
               CMP   EAX, 0aH
               JNE   exit

               LEA   RCX, OFFSET $ok
               CALL  puts
exit:
               ADD   RSP, 40
               RET 0
foo:
               MOV   R8,QWORD PTR [$L_180fa2570]
               MOV   RAX,R8
               RET
bar:
               MOV   RAX, 1
               LEA   RCX,__ImageBase
               MOVZX EDX,BYTE PTR [RAX+RCX*1+((IMAGEREL N_180fa2570)+7)]
               MOV   EAX, EDX
               RET


.DATA
$OK DB	"ok", 00H

$L_180fa24e0:
               BYTE 070H
               BYTE 000H
               BYTE 000H
               BYTE 000H
               BYTE 000H
               BYTE 000H
               BYTE 000H
               BYTE 000H

$L_180fa2570:
N_180fa2570    QWORD $L_180fa24e0
               BYTE 00aH
               BYTE 009H
               BYTE 00aH
               BYTE 00cH
               BYTE 000H
               BYTE 000H
               BYTE 000H
               BYTE 000H

END
