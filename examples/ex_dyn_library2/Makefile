CC="gcc"
CFLAGS=
EXEC=

all: ex.c fun.c
	$(CC) fun.c -fPIC -shared -lm $(CFLAGS) -o fun.so
	$(CC) ex.c $(CFLAGS)  fun.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex >/tmp/res.txt
	diff out.txt /tmp/res.txt && echo TEST OK
