


## Introduction
The files reader.pl and disasm extract a series of facts from a binary and combine it into a datalog program
which can be printed in several formats.

## Tasks



## Running the analysis
Example usage
`./disasm ../examples/ex1/ex`

The prolog module `disasm`  takes care of extracting symbols and sections
from an elf binary. Then, it calls souffle_disasm to decode the extracted sections.
Finally, it calls souffle and pretty prints the results.
This uses:

 * `./elf_extract.sh` to extract a list of sections and symbols from the binary
 * objcopy to extract specific sections from the binary
 * and `souffle_disasm` to decode sections into facts



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
