.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@
ex: ex_ldr_pc_rel_reg.s
	arm-linux-gnueabihf-gcc -no-pie -o $@ $^
clean:
	rm -f ex out.txt
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
