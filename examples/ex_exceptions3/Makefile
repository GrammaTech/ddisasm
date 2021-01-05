CXX="g++"
EXEC=

all: ex.cpp
	$(CXX) ex.cpp $(CXXFLAGS) -std=c++11 -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
