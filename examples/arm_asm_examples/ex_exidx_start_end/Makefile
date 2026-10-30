.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@
ex: ex_original.s
	arm-linux-gnueabihf-gcc	$(CFLAGS) -o $@ $^
clean:
	rm -f ex out.txt *.gtirb
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
