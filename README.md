

run the prolog module that generates the datalog inputs
it generates an input for souffle and one for bddbddb

./disasm examples/bzip/bzip2

run the analysis with bddbddb

`java -jar bddbddb-full.jar examples/ex1/ex.bdd

run the analysis with souffle

`souffle examples/ex1/ex.dl

generate an executable that can be run later. It is considerably faster.


`souffle examples/ex1/ex.dl -o examples/ex1/ex_prog

