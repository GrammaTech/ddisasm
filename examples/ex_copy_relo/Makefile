CC="gcc"
CFLAGS=
EXEC=

all: ex.c foo.c
	$(CC) -c foo.c  $(CFLAGS) -o foo.o -fPIC
	$(CC) -c ex.c  $(CFLAGS) -o ex.o
	$(CC) ex.o foo.o  $(CFLAGS) -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex ex.unstripped out.txt *.s *.lib *.exp *.o *.err *.gtirb *.i
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
