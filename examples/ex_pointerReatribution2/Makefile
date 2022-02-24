CC="gcc"
CFLAGS=
EXEC=

all: ex.c
	$(CC) ex.c  $(CFLAGS) -o ex
	@ echo "A" | $(EXEC) ./ex > out.txt
	@ echo "B" | $(EXEC) ./ex >> out.txt
	@ echo "C" | $(EXEC) ./ex >> out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@ echo "A" | $(EXEC) ./ex > /tmp/res.txt
	@ echo "B" | $(EXEC) ./ex >> /tmp/res.txt
	@ echo "C" | $(EXEC) ./ex >> /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
