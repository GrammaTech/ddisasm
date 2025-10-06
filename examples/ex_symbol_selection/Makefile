CC="gcc"
CFLAGS=
EXEC=

all: ex.c bar.c data.c fun.c
	# Put bar.c first to make the `my_strings` defined in bar.c be the first
	# symbol in the symbol set with the same name.
	$(CC) bar.c data.c fun.c -shared $(CFLAGS) -fPIC -o  fun.so
	$(CC) ex.c   $(CFLAGS)  fun.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex > out.txt
clean:
	rm -f ex fun.so out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
