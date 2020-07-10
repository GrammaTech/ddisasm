
all: hello.c
	aarch64-linux-gnu-gcc hello.c -o hello
	@qemu-aarch64 -L /usr/aarch64-linux-gnu hello > out.txt
clean:
	rm -f hello out.txt
check:
	qemu-aarch64 -L /usr/aarch64-linux-gnu hello > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
