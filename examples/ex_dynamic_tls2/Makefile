CC="gcc"
CFLAGS=
EXEC=

all: ex.c foo.c fun.c
	$(CC) -c foo.c -fPIC $(CFLAGS) -o foo.o
	$(CC) fun.c foo.o -shared $(CFLAGS) -fPIC -o fun.so
	$(CC) ex.c $(CFLAGS) fun.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -f ex fun.so foo.o out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
