CC="gcc"
CFLAGS=


all: ex.c
	$(CC) ex.c  $(CFLAGS) -o ex
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files
check:
	@./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
