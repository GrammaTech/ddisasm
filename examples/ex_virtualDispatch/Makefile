CXX="g++"
all: ex.cpp
	$(CXX) ex.cpp $(CFLAGS) -o ex
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr *.s *.old*  dl_files
check:
	@./ex >/tmp/res.txt
	@ bash ./test.sh
