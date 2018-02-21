all: ex.c 
	gcc ex.c  -o ex 
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.s ex.old dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh

