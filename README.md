


## Introduction
The files reader.pl and disasm extract a series of facts from a binary and combine it into a datalog program
which can be printed in several formats.

## Tasks



## Running the analysis
run the prolog module that generates the datalog inputs
it generates an input for souffle and one for bddbddb

`./disasm examples/bzip/bzip2`

This uses:

 * `./elf_extract.sh` to extract a list of sections and symbols from the binary
 * objcopy to extract specific sections from the binary
 * and `x64show` to decode sections into tsl code

Once the datalog input has been generated, it can be run with different engines:

* run the analysis with bddbddb

`java -jar bddbddb-full.jar examples/ex1/ex.bdd`

* run the analysis with souffle

`souffle examples/ex1/ex.dl`
souffle souffle_rules.pl -I ../examples/bzip/ -j 8  > ../examples/bzip/valid.txt

* generate an executable with souffle that can be run later.
It is considerably faster.

`souffle examples/ex1/ex.dl -o examples/ex1/ex_prog`

## References
1. Souffle: "On fast large-scale program analysis in Datalog" CC2016
 - PDF: http://souffle-lang.org/pdf/cc.pdf
 - License: Universal Permissive License (UPL)
 - Web: https://github.com/souffle-lang/souffle
 
2. Porting Doop from LogicBlox to souffle
 - https://yanniss.github.io/doop2souffle-soap17.pdf

3. bddbddb
 - Web: http://bddbddb.sourceforge.net/
 - Papers:   https://suif.stanford.edu/papers/pldi04.pdf
             https://people.csail.mit.edu/mcarbin/papers/aplas05.pdf

4. Control Flow Integrity for COTS Binaries
   - PDF: http://stonecat/repos/reading/papers/12313-sec13-paper_zhang.pdf

5. Alias analysis for Assembly by Brumley at CMU:
  http://reports-archive.adm.cs.cmu.edu/anon/anon/usr/ftp/2006/CMU-CS-06-180R.pdf
