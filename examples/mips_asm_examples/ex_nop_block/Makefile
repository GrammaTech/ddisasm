.PHONY: clean check
out.txt: ex
	@qemu-mips -L /usr/mips-linux-gnu $^ 2 > $@
ex: ex_original.s
	mips-linux-gnu-gcc -no-pie -o $@ $^ -lm
clean:
	rm -f ex out.txt ex.gtirb
check: ex
	qemu-mips -L /usr/mips-linux-gnu $^ 2 > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
