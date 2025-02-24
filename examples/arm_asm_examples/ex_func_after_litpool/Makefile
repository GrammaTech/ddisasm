AS=arm-linux-gnueabihf-as
LD=arm-linux-gnueabihf-ld
STRIP=arm-linux-gnueabihf-strip

all: ex

ex: ex_original.s
	$(AS) -march=armv7-a -o ex.o ex_original.s
	$(LD) -o ex ex.o
	$(STRIP) ex
	@qemu-arm -L /usr/arm-linux-gnueabihf ./ex > out.txt

clean:
	rm -f ex ex.o out.txt

check:
	qemu-arm -L /usr/arm-linux-gnueabihf ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
