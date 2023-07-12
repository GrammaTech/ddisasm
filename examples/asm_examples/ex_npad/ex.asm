.MODEL FLAT, STDCALL
.686P
.XMM

INCLUDE listing.inc
INCLUDELIB ucrt

PUBLIC  main
EXTRN   puts:PROC

.data
FOR arg:=<X>, <1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>
    $&arg DB '&arg', 00H
ENDM

.code
main:
    push  ebp
    mov ebp, esp

FOR arg:=<X>, <1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>
    push  OFFSET $&arg
    call  puts
    add esp, 4
    jmp @F
    npad &arg
@@:
ENDM

    xor eax, eax
    pop ebp
    ret 0
END
