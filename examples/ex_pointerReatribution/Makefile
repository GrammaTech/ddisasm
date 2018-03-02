all: ex.c 
	clang ex.c  -o ex -O1
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr *.s *.old*  dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh


