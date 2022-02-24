CC=aarch64-linux-gnu-gcc

TARGETS=ex out.txt

.PHONY: all clean
all: ex
ex: src.s
	$(CC) $^ -o $@
clean:
	rm -f $(TARGETS) *.gtirb
