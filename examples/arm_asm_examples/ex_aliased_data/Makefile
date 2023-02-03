.PHONY: clean check
out.txt: ex
	@qemu-arm -L /usr/arm-linux-gnueabihf $^ > $@
# ex_aliased_data is only meaningful when stripped; ddisasm only gets
# confused about fake code without mapping symbols
# We currently keep __libc_csu* symbols due to issue#493
ex: ex.unstripped
	arm-linux-gnueabihf-strip --strip-unneeded --keep-symbol=__libc_csu_init --keep-symbol=__libc_csu_fini -o $@ $^
ex.unstripped: ex_aliased_data.s
	arm-linux-gnueabihf-gcc -pie -o $@ $^
clean:
	rm -f ex ex.unstripped out.txt
check: ex
	qemu-arm -L /usr/arm-linux-gnueabihf $^ > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
