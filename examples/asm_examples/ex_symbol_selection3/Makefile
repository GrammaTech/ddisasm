CC=gcc

all: libfoo.so ex

libfoo.so: libfoo.c
	$(CC) -shared -fPIC -o $@ $<

ex: ex_original.s
	$(CC) -pie -Wl,-T,linker-script.ld ex_original.s ./libfoo.so -o $@
	@./ex > out.txt
clean:
	rm -f ex libfoo.so out.txt
check:
	./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
