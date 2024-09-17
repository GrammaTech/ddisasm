.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@

ex: ex_original.s
	arm-linux-gnueabihf-gcc -nostartfiles -o $@ $^
clean:
	rm -f ex out.txt
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
