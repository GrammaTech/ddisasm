
all: ex_original.s
	gcc -o ex ex_original.s
	@./ex > out.txt
clean:
	rm -f ex out.txt
check:
	@./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
