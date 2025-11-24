.PHONY: clean check
all: ex.c fun.so.stripped.s
	mips-linux-gnu-gcc -o fun.so fun.so.stripped.s -Wl,--no-as-needed -l:libc.so.6 --shared
	mips-linux-gnu-gcc ex.c -O0 fun.so -o ex
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. qemu-mips -L /usr/mips-linux-gnu ./ex > out.txt
clean:
	rm -f ex fun.so out.txt
	rm -fr ex.unstripped ex.s fun.so.s *.old*  dl_files *.gtirb
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. qemu-mips -L /usr/mips-linux-gnu ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
