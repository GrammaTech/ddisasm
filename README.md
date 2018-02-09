


## Introduction

The analysis contains three parts:

 - The c++ files generate a binary src/souffle_disasm which takes care
 of reading an elf file and generating several `.facts` files that
 represent the inital problem.
 
 - `src/souffle_rules.dl` is the specification of the analysis in
 datalog.  It takes the basic facts and computes likely EAs, chunks of
 code, etc. The results are stored in `.csv` files.
 
 - `src/disasm_driver.pl` is a prolog module that calls souffle_disasm
 first, then it calls souffle and finally reads the results from the
 analysis and prints the assembler code.
 
## Dependencies

- The project is prepared to be built with GTScons and has to be located
in the grammatech trunk directory.

- The analysis depends on souffle being installed, 
in particular the 64 bits version at https://github.com/cfallin/souffle.git

- The pretty printer is (for now) written in prolog. It requires some prolog environment
to be installed (preferably SWI-prolog).

## Building souffle_disasm



`/trunk/datalog_disasm/build`


## Running the analysis
Once souffle_disasm is built, we can run complete analysis on a file
by calling `/src/disasm'`.
For example, we can run the analysis on one of the examples as
follows:

`cd src` `./disasm ../examples/ex1/ex`


 
## Current status

- The analysis can disassemble correctly `ex1` and `ex_virtualDispatch`, even if these
are stripped of their symbols (using `strip --strip-unneeded`).

- The analysis has some conficts (segments of code that overlap) with
`ex_switch` and more of them are left unresolved with the stripped
version. This is normal, right now there is only one heuristic to
resolve conflicts based on function symbols.

- So far, not being able (not even trying) to compute indirect jumps or calls
has not been a problem.

### Issues/TODOs

- Compute additional seeds based on computed jumps/calls and exceptions.

- Resolve conflicts based on heuristics.


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
  
6. Reassembleable Disassembling

7. Ramblr: Making Reassembly Great again
