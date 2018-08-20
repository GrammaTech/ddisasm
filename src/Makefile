STANDALONE=./../standalone_compilation
GTIRB_BASE ?= ../../gtirb

CC ?= g++
CFLAGS=-c -Werror -Wall -Wpointer-arith  -Wno-unused-local-typedefs -fvisibility=hidden -g3  -mno-3dnow  -mtune=generic -pthread -std=c++17 -Wno-shadow -DEXPORT_GTR_SYMBOLS=1 -DEXPORT_TSL_SYMBOLS=1 -no-pie -DRAM_DOMAIN_SIZE=64 -DGSL_USE_STD_BYTE
INCLUDE= -I /usr/local/include -I $(STANDALONE)/include/ -I ./../../ -I $(GTIRB_BASE)/include/
SOURCES= decoder_main.cpp Dl_decoder.cpp Datalog_visitor_x64.cpp Dl_operator.cpp Dl_instruction.cpp Dl_operator_table.cpp Elf_reader.cpp
OBJECTS=$(SOURCES:.cpp=.o)

DATALOG_SOURCES=datalog/code_inference.dl datalog/disasm datalog/empty_range.dl	datalog/function_inference.dl  datalog/main.dl datalog/symbolization.dl datalog/use_def_analysis.dl datalog/data_access_analysis.dl datalog/float_operations.dl datalog/jump_operations.dl datalog/printable_chars.dl datalog/traverse_code.dl datalog/value_analysis.dl

LDFLAGS= -fvisibility=hidden  -mtune=generic  -Wl,--exclude-libs,libc++.a:libc++abi.a:libunwind.a -L$(GTIRB_BASE)/bin

LINK= -L$(STANDALONE)/lib -L/usr/local/lib -L.  -lpthread -lrt -lstring  -ldetcheck -lisax_thin_decoder_x64 -ltsl_rtg_x64 -ltsl_rtg_generic  -lm -lisax_core_x64 -lisax -lgt_assert -lgt_message -lgt_abort -lgtr_compat -lrt -ldatalog_visitor_x64 -lboost_program_options -lboost_system -lboost_serialization -lc++  -lc++abi  -lpthread -ldl -no-pie -lgtirb

all: ../bin/datalog_decoder ../bin/souffle_disasm

../bin/souffle_disasm.cpp: datalog/*.dl
	souffle datalog/main.dl -g ../bin/souffle_disasm.cpp

# Compile generated Souffle code. This needs different flags to avoid
# warnings. We also need to make sure that the preprocessor flags
# (particularly RAM_DOMAIN_SIZE) match those used when compiling
# Souffle itself.
# Finally, always optimize. It improves performance significantly and
# we're unlikely to need to debug this code.
../bin/souffle_disasm.o: ../bin/souffle_disasm.cpp
	$(CC) -O2 -std=c++11 -c ../bin/souffle_disasm.cpp -o ../bin/souffle_disasm.o -D__EMBEDDED_SOUFFLE__ -DRAM_DOMAIN_SIZE=64 -Wno-narrowing -Wno-unused-but-set-variable

../bin/souffle_disasm: ../bin/souffle_disasm.o disasm_main.o
	$(CC) -g3 -o ../bin/souffle_disasm $(LDFLAGS) ../bin/souffle_disasm.o disasm_main.o $(LINK)

../bin/datalog_decoder: $(OBJECTS) libdatalog_visitor_x64.a | $(STANDALONE)
	$(CC) -o ../bin/datalog_decoder $(LDFLAGS) decoder_main.o Dl_decoder.o $(LINK)

libdatalog_visitor_x64.a: $(OBJECTS) | $(STANDALONE)
	ar rc libdatalog_visitor_x64.a Datalog_visitor_x64.o Dl_operator.o Dl_instruction.o Dl_operator_table.o Elf_reader.o
	ranlib libdatalog_visitor_x64.a

%.o: %.cpp | $(STANDALONE)
	$(CC) -o $@ $(CFLAGS)   $< $(INCLUDE)

clean:
	rm -f *.a *.o ../bin/souffle_disasm* ../bin/datalog_decoder

$(STANDALONE):
	tar xvjf /u4/TARBALLS/datalog_disasm/standalone_compilation.tar.bz2 -C ../
