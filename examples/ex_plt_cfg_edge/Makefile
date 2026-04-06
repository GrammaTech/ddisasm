CC="gcc"
CFLAGS=
EXEC=

all: fun.c ex.c
	$(CC) -fPIC -shared $(CFLAGS) fun.c -o fun.so
	$(CC) ex.c -no-pie -fno-PIC $(CFLAGS) -o ex -L. -l:fun.so
	@ LD_LIBRARY_PATH=. $(EXEC) ./ex > out.txt
clean:
	rm -f ex ex.gtirb fun.so *.s *.i *.o out.txt
check:
	@ LD_LIBRARY_PATH=. $(EXEC) ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
