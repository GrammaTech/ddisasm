CC="gcc"
CFLAGS=
EXEC=


all: ex.c
	$(CC) ex.c fun.c  $(CFLAGS) -fPIC -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
