CC="gcc"
CFLAGS=

all: ex.c foo.c
	$(CC) foo.c -o libfoo.so -shared $(CFLAGS) -fPIC -Wl,--version-script=libfoo.map
	$(CC) ex.c $(CFLAGS) libfoo.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -f ex libfoo.so *.s *.gtirb out.txt
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
