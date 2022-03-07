# Running this test on ARM creates address collisions with instructions that
# may be symbolized and debug relocations. ARM makes this collisions more
# likely since instructions are aligned and fixed size.

CC=arm-linux-gnueabihf-gcc
CFLAGS=-g -Og
EXEC=qemu-arm -L /usr/arm-linux-gnueabihf

.PHONY: all clean check

all: out.txt
ex: ex.o
	$(CC) $(CFLAGS) -o $@ $^
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^
out.txt: ex
	@ $(EXEC) ./ex > $@
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.o *.old*  dl_files *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
