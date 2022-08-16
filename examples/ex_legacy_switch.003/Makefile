CC="gcc"
CFLAGS=
EXEC=

all: ex.c
	$(CC) ex.c $(CFLAGS) -o ex
	@ for CHAR in 750 800 900 700 500 250 100 200 600; do $(EXEC) ./ex.exe "$$CHAR"; done > out.txt
clean:
	rm -f ex.exe *.txt *.s *.lib *.exp *.o *.err
check:
	@ for CHAR in 750 800 900 700 500 250 100 200 600; do $(EXEC) ./ex.exe "$$CHAR"; done > check.txt
	@ diff out.txt check.txt && echo TEST OK
