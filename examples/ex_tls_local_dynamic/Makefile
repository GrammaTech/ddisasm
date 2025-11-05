CC="gcc"
CFLAGS=
EXEC=

all: tls.c tls_def.c ex.c
	$(CC) -fPIC -c tls.c "-ftls-model=local-dynamic" $(CFLAGS) -o tls.o
	$(CC) -fPIC -c tls_def.c "-ftls-model=local-dynamic" $(CFLAGS) -o tls_def.o
	$(CC) -shared -o libtls.so tls.o tls_def.o
	$(CC) ex.c -fPIC $(CFLAGS) -ltls -L./ -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.old* *.s dl_files *.gtirb *.o *.so
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
