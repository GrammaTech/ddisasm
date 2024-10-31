CXX="g++"
EXEC=

all: ex_original.s
	# NOTE: `-T linker-script.ld`
	# This is to place .gcc_except_table *before* .note.gnu.build-id
	# so that the reference label for the end of the section is aligned
	# with the adjacent section. Otherwise, the next section can be some
	# discarded one, which would prevent from demonstrating the issue.
	#
	# With this example, if a boundary_sym_expr is not correctly created
	# for symbol_minus_symbol (either the first or the second symbol, or
	# both), the assembler will fail with
	#
	# "Error: invalid operands (.note.gnu.property and .gcc_except_table
	# sections) for '-'"
	#
	$(CXX) -T linker-script.ld -o ex ex_original.s
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped *.old*  dl_files *.gtirb
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
