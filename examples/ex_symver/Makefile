CC="gcc"
CFLAGS=
EXEC=

all: ex.c ex2.c ex3.c foo.c
	$(CC) bar.c -o libbar.so -shared $(CFLAGS) -fPIC -Wl,--version-script=libbar.map
	$(CC) foo.c libbar.so -o libfoo.so -shared $(CFLAGS) -fPIC -Wl,--version-script=libfoo.map
	$(CC) ex.c $(CFLAGS) libfoo.so libbar.so -o ex
	$(CC) ex2.c $(CFLAGS) libfoo.so libbar.so -o ex2
	$(CC) ex3.c $(CFLAGS) libfoo.so libbar.so -o ex3
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex > out.txt
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex2 >> out.txt
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex3 >> out.txt
clean:
	rm -f ex ex2 ex3 libfoo.so libbar.so *.s *.gtirb out.txt
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex >/tmp/res.txt
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex2 >> /tmp/res.txt
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex3 >> /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
