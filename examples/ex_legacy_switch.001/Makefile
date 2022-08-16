CC="gcc"
CFLAGS=
EXEC=

all: ex.c
	$(CC) ex.c $(CFLAGS) -o ex
	@ for CHAR in A B C D E F G H; do $(EXEC) ./ex.exe "$$CHAR"; done > out.txt
clean:
	rm -f ex.exe *.txt *.s *.lib *.exp *.o *.err
check:
	@ for CHAR in A B C D E F G H; do $(EXEC) ./ex.exe "$$CHAR"; done > check.txt
	@ diff out.txt check.txt && echo TEST OK
