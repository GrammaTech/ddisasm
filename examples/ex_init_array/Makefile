CXX="g++"
CXXFLAGS=
EXEC=

all: ex1.c ex2.c
	$(CXX) ex1.c ex2.c  $(CXXFLAGS) -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
