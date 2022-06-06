CC=aarch64-linux-gnu-gcc
EXEC=qemu-aarch64 -L /usr/aarch64-linux-gnu

TARGETS=ex out.txt

.PHONY: all clean check
all: out.txt
check: out.txt
ex: src.s
	$(CC) $^ -o $@
out.txt: ex
	$(EXEC) $^ > $@
clean:
	rm -f $(TARGETS) *.gtirb
