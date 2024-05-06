
all: ex_original.s fun.s
	gcc -shared -o fun.so fun.s
	gcc -o ex ex_original.s -L. -l:fun.so
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr fun.so fun.so.unstripped fun.so.s *.old*  dl_files *.gtirb
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
