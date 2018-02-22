all: ex_virtual.cpp
	g++ ex_virtual.cpp -o ex
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr *.s *.old*  dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh
