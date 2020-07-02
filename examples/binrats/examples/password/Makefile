AMD64CC=x86_64-linux-gnu-gcc
ARM64CC=aarch64-linux-gnu-gcc

CFLAGS=-g

TESTNAME=password

DD=../../../build/bin/ddisasm
OUT_AMD64=$(TESTNAME)_amd64
OUT_ARM64=$(TESTNAME)_arm64

.PHONY: all clean

all: amd64 arm64

amd64: $(TESTNAME).c
	$(AMD64CC) $^  $(CFLAGS) -o $(OUT_AMD64)
	$(DD) $(OUT_AMD64) --asm=amd64.s $(DD_FLAGS)

arm64: $(TESTNAME).c
	$(ARM64CC) $^  $(CFLAGS) -o $(OUT_ARM64)
	$(DD) $(OUT_ARM64) --asm=arm64.s $(DD_FLAGS)

clean:
	rm -f $(OUT_ARM64) $(OUT_AMD64) arm64.s amd64.s
