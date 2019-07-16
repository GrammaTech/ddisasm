CXX="g++"
all: ex.cpp
    $(CXX) ex.cpp $(CFLAGS) -std=c++11 -o ex
    ./ex > out.txt
clean:
    rm -f ex out.txt
    rm -fr ex.unstripped *.s *.old*  dl_files
check:
    ./ex >/tmp/res.txt
    bash ./test.sh
