CC=gcc

all: libfoo.so ex

libfoo.so: libfoo.c
	$(CC) -shared -fPIC -o $@ $<

ex: ex_original.s
	$(CC) -pie -Wl,-T,linker-script.ld ex_original.s -L. -lfoo -Wl,-rpath,'$$ORIGIN' -o $@
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > out.txt
clean:
	rm -f ex libfoo.so out.txt
check:
	@LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
