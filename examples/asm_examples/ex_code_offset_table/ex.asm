INCLUDELIB libcmt

EXTERN __ImageBase:BYTE
PUBLIC main
EXTRN puts:PROC

.CODE
main:
               SUB   RSP, 40

               XOR   RAX, RAX
               XOR   RCX, RCX
               LEA   RCX, index

               MOV   R11, RCX
               MOV   RAX, RDX
               MOV   RCX, RDX
               MOV   EDX, DWORD PTR [R11]          ; load index from data
               LEA   R8,  QWORD PTR [$L_180017488] ; load offset table address
               MOV   R8,  QWORD PTR [R8+RDX*8-16]  ; load offset at index
               LEA   R9,  QWORD PTR [$L_180015E50] ; reference address
               ADD   R8,  R9
               CALL  R8

               ADD   RSP, 40
               RET   0


$L_180015e50:
foo:
               SUB   RSP, 40
               LEA   RCX, OFFSET $bad
               CALL  puts
               ADD   RSP, 40
               RET

bar:
               SUB   RSP, 40
               LEA   RCX, OFFSET $bad
               CALL  puts
               ADD   RSP, 40
               RET

baz:
               SUB   RSP, 40
               LEA   RCX, OFFSET $good
               CALL  puts
               ADD   RSP, 40
               RET

qux:
               SUB   RSP, 40
               LEA   RCX, OFFSET $bad
               CALL  puts
               ADD   RSP, 40
               RET

               BYTE 0CCH


.DATA
$bad           DB	"bad", 00H
$good          DB	"good", 00H

index DWORD 4

$L_180017488:
N_180017488  QWORD (foo - $L_180015E50)
             QWORD (bar - $L_180015E50)
             QWORD (baz - $L_180015E50)
             QWORD (qux - $L_180015E50)

END
