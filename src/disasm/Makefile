STANDALONE=./../../standalone_compilation

CC=gcc
CFLAGS=-c -Werror -Wall -Wpointer-arith -Wshadow -Wno-unused-local-typedefs -fvisibility=hidden -g3 -m32 -march=i686 -mtune=generic -pthread -std=c++1y -std=c++1y -Wno-shadow -Wno-shadow -O0 
INCLUDE= -I $(STANDALONE)/include/ -I ./../../
SOURCES= disasm.cpp Table.cpp
OBJECTS=$(SOURCES:.cpp=.o)
LDFLAGS= -fvisibility=hidden -m32 -march=i686 -mtune=generic -static-libgcc -Wl,--exclude-libs,libstdc++.a
LINK= -L$(STANDALONE)/lib -L.  -lstring  -ldetcheck -lisax_thin_decoder_x64 -ltsl_rtg_x64 -ltsl_rtg_generic  -lm -lisax_core_x64 -lisax -lboost_program_options -lstdc++ -lpthread

all: ../../bin/disasmDriver

../../bin/disasmDriver: main.o $(OBJECTS) libdisasmDriver_x64.a | $(STANDALONE)
	$(CC) -o ../../bin/disasmDriver $(LDFLAGS) main.o $(OBJECTS) $(LINK)


libdisasmDriver_x64.a: $(OBJECTS) | $(STANDALONE)
	ar rc libdisasmDriver_x64.a $(OBJECTS)
	ranlib libdisasmDriver_x64.a

%.o: %.cpp | $(STANDALONE)
	$(CC) -o $@ $(CFLAGS)   $< $(INCLUDE)
	
clean:
	rm -f *.a *.o ../../bin/disasmDriver

$(STANDALONE):
	tar xvjf /u4/TARBALLS/datalog_disasm/standalone_compilation.tar.bz2 -C ../../
