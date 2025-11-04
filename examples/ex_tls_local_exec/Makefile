CC="gcc"
CFLAGS=
EXEC=

all: ex.c
	$(CC) ex.c "-ftls-model=local-exec" $(CFLAGS) -o ex
	@$(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr test.unstripped *.old* *.s dl_files *.gtirb *.o *.so
check:
	@$(EXEC) ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
