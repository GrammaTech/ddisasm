STANDALONE=./../standalone_compilation

CC=gcc
CFLAGS=-c -Werror -Wall -Wpointer-arith -Wshadow -Wno-unused-local-typedefs -fvisibility=hidden -g3 -m32 -march=i686 -mtune=generic -pthread -std=c++1y -std=c++1y -Wno-shadow -Wno-shadow  -DEXPORT_GTR_SYMBOLS=1
INCLUDE= -I $(STANDALONE)/include/ -I ./../../
SOURCES= decoder_main.cpp Dl_decoder.cpp Datalog_visitor_x64.cpp Dl_operator.cpp Dl_instruction.cpp Dl_operator_table.cpp Elf_reader.cpp
OBJECTS=$(SOURCES:.cpp=.o)

DATALOG_SOURCES=datalog/code_inference.dl datalog/disasm datalog/empty_range.dl	datalog/function_inference.dl  datalog/main.dl datalog/symbolization.dl datalog/use_def_analysis.dl datalog/data_access_analysis.dl datalog/float_operations.dl datalog/jump_operations.dl datalog/printable_chars.dl datalog/traverse_code.dl datalog/value_analysis.dl

LDFLAGS= -fvisibility=hidden -m32 -march=i686 -mtune=generic -static-libgcc -Wl,--exclude-libs,libstdc++.a
LINK= -L$(STANDALONE)/lib -L.  -lstring  -ldetcheck -lisax_thin_decoder_x64 -ltsl_rtg_x64 -ltsl_rtg_generic  -lm -lisax_core_x64 -lisax -lgt_assert -lgt_message -lgt_abort -lgtr_compat  -ldatalog_visitor_x64 -lboost_program_options  -lstdc++ -lpthread

all: ../bin/datalog_decoder ../bin/souffle_disasm

../bin/souffle_disasm: $(DATALOG_SOURCES)
	souffle datalog/main.dl -o ../bin/souffle_disasm

../bin/datalog_decoder: $(OBJECTS) libdatalog_visitor_x64.a | $(STANDALONE)
	$(CC) -o ../bin/datalog_decoder $(LDFLAGS) decoder_main.o Dl_decoder.o $(LINK)


libdatalog_visitor_x64.a: $(OBJECTS) | $(STANDALONE)
	ar rc libdatalog_visitor_x64.a Datalog_visitor_x64.o Dl_operator.o Dl_instruction.o Dl_operator_table.o Elf_reader.o
	ranlib libdatalog_visitor_x64.a

%.o: %.cpp | $(STANDALONE)
	$(CC) -o $@ $(CFLAGS)   $< $(INCLUDE)
clean:
	rm -f *.a *.o ../bin/souffle_disasm ../bin/datalog_decoder

$(STANDALONE):
	tar xvjf /u4/TARBALLS/datalog_disasm/standalone_compilation.tar.bz2 -C ../
