all: ex.c fun.c
	gcc ex.c fun.c -o ex -fPIC
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.s ex.old dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh
