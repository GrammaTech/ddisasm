all: ex_switch.c 
	gcc -o ex ex_switch.c
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.s ex.old dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh

