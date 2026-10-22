CC="gcc"
CFLAGS=
EXEC=

all: ex.c
	$(CC) ex.c $(CFLAGS) -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex ex.unstripped out.txt *.s *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK

