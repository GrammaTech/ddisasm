INCLUDELIB libcmt

EXTERN __ImageBase:BYTE

EXTRN puts:PROC

.CODE


print_ok1 PROC EXPORT
                JMP print_ok
print_ok1 ENDP

print_ok2 PROC EXPORT
                JMP print_ok
print_ok2 ENDP

print_ok3 PROC EXPORT
                JMP print_ok
print_ok3 ENDP


print_ok:
                LEA   RCX, OFFSET $OK
                CALL  puts

exit:
                RET 0
.DATA
$OK DB	"ok", 00H


END
