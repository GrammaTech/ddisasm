.PHONY: clean
ex: ex_original.s
	arm-linux-gnueabihf-gcc	-o $@ $^ -nostartfiles
clean:
	rm -f ex out.txt
