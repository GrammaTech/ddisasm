CC="gcc"
CFLAGS=

all: ex.c fun.c
	$(CC) fun.c  -shared $(CFLAGS) -fPIC -o  fun.so
	$(CC) ex.c   $(CFLAGS)  fun.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
