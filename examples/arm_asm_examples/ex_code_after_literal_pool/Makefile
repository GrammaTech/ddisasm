.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@
ex: ex_code_after_literal_pool.s
	arm-linux-gnueabihf-gcc	-o $@ $^
clean:
	rm -f ex out.txt
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
