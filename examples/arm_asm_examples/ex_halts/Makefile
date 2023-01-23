.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@
ex: ex_halts.s
	arm-linux-gnueabihf-gcc	-o $@ $^
clean:
	rm -f ex out.txt ex.gtirb
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
