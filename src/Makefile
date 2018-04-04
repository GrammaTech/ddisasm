
CC=gcc
CFLAGS=-c -Werror -Wall -Wpointer-arith -Wshadow -Wno-unused-local-typedefs -fvisibility=hidden -g3 -m32 -march=i686 -mtune=generic -pthread -std=c++1y -std=c++1y -Wno-shadow -Wno-shadow  -DEXPORT_GTR_SYMBOLS=1
INCLUDE= -I ./../standalone_compilation/include/ -I ./../../
SOURCES= souffle_disasm.cpp Dl_decoder.cpp Datalog_visitor_x64.cpp Dl_operator.cpp Dl_instruction.cpp Dl_operator_table.cpp Elf_reader.cpp
OBJECTS=$(SOURCES:.cpp=.o)

LDFLAGS= -fvisibility=hidden -m32 -march=i686 -mtune=generic -static-libgcc -Wl,--exclude-libs,libstdc++.a
LINK= -L./../standalone_compilation/lib -L.  -lstring  -ldetcheck -lisax_thin_decoder_x64 -ltsl_rtg_x64 -ltsl_rtg_generic  -lm -lisax_core_x64 -lisax -lgt_assert -lgt_message -lgt_abort -lgtr_compat  -ldatalog_visitor_x64 -lboost_program_options  -lstdc++ -lpthread

all: souffle_disasm

souffle_disasm: $(OBJECTS) libdatalog_visitor_x64.a ../standalone_compilation
    $(CC) -o souffle_disasm $(LDFLAGS) souffle_disasm.o Dl_decoder.o $(LINK)


libdatalog_visitor_x64.a: $(OBJECTS) ../standalone_compilation
    ar rc libdatalog_visitor_x64.a Datalog_visitor_x64.o Dl_operator.o Dl_instruction.o Dl_operator_table.o Elf_reader.o
    ranlib libdatalog_visitor_x64.a

%.o: %.cpp ../standalone_compilation
    $(CC) -o $@ $(CFLAGS)   $< $(INCLUDE)
clean:
    rm -f *.a *.o souffle_disasm
