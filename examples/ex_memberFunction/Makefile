CXX="g++"
EXEC=

all: ex.cpp
	$(CXX) ex.cpp $(CXXFLAGS) -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex ex.unstripped out.txt *.s *.lib *.exp *.o *.err *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
