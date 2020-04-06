
all: ex_original.s
	arm-linux-gnueabihf-gcc	 ex_original.s -pie -o ex
	@qemu-arm -L /usr/arm-linux-gnueabihf ex > out.txt
clean:
	rm -f ex out.txt
check:
	qemu-arm -L /usr/arm-linux-gnueabihf ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
