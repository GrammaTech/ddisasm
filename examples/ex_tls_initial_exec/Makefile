CC="gcc"
CFLAGS=
EXEC=

all: ex.c tls_def.c test.c
	$(CC) -fPIC -c ex.c "-ftls-model=initial-exec" $(CFLAGS) -o ex.o
	$(CC) -fPIC -c tls_def.c "-ftls-model=initial-exec" $(CFLAGS) -o tls_def.o
	$(CC) -shared -o libtls.so ex.o tls_def.o
	$(CC) test.c -fPIC $(CFLAGS) -ltls -L./ -o test
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./test > out.txt
clean:
	rm -f test out.txt
	rm -fr test.unstripped *.old* *.s dl_files *.gtirb *.o *.so
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./test > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
