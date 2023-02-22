CC="gcc"
CFLAGS=

all: ex.c fun.c fun_static.c
	$(CC) fun.c  -shared $(CFLAGS) -fPIC -o  fun.so
	$(CC) fun_static.c  -shared $(CFLAGS) -fPIC -o  fun_static.so
	$(CC) ex.c   $(CFLAGS)  fun.so fun_static.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -fr ex ex.unstripped *.so *.s *.i *.o *.gtirb out.txt
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex >/tmp/res.txt
	@diff out.txt /tmp/res.txt && echo TEST OK
