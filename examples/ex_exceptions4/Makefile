CXX="g++"
EXEC=

all: ex.cpp
	# NOTE: `-T linker-script.ld`
	# This is to place .gcc_except_table *before* .note.gnu.build-id
	# so that the reference label for the end of the section is aligned
	# with the adjacent section.
	#
	# With this example, if a boundary_sym_expr is not correctly created
	# for symbol_minus_symbol, the assembler will fail with
	# "Error: invalid operands for '-'"
	$(CXX) ex.cpp $(CXXFLAGS) -T linker-script.ld -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.s *.old*  dl_files *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
