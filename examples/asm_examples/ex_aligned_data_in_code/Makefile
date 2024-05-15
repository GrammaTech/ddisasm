
all: ex_original.s
	gcc ex_original.s -o ex
	gcc ex_original2.s -o ex2
	@./ex > out.txt
	@./ex2 > out2.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old*  dl_files *.gtirb
	rm -f ex2 out2.txt
	rm -fr ex2.unstripped ex2.s
check:
	./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
	./ex2 > /tmp/res2.txt
	@ diff out2.txt /tmp/res2.txt && echo TEST OK
