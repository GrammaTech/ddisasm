AMD64CC=x86_64-linux-gnu-gcc
ARM64CC=aarch64-linux-gnu-g++

CFLAGS=-g


all: hello.c
	$(AMD64CC) hello.c  $(CFLAGS) -o hello_amd64
	ddisasm hello_amd64 --asm=amd64.s
	$(ARM64CC) hello.c  $(CFLAGS) -o hello_arm64
	ddisasm hello_arm64 --asm=arm64.s

clean:
	rm hello_amd64 hello_arm64 arm64.out.txt amd64.out.txt
