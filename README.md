Datalog Disassembly
===================

A *fast* disassembler which is *accurate* enough for the resulting
assembly code to be reassembled.  The disassembler implemented using
the datalog ( [souffle](https://github.com/souffle-lang/souffle))
declarative logic programming language to compile reverse engineering
and binary analysis rules and heuristics.  The disassembler first
parses ELF file information and decodes a superset of possible
instructions to create an initial set of datalog facts.  These facts
are analyzed to identify *code location*, *symbolization*, and
*function boundaries*.  The results of this analysis, a refined set of
datalog facts, are then translated to the GTIRB intermediate
representation for binary analysis and reverse engineering.  The
[GTIRB pretty printer](https://github.com/grammatech/XXXXXXXX) may
then be used to pretty print the GTIRB to reassemblable assembly code.

## Introduction

The analysis contains three parts:

- The c++ files generate a binary `bin/datalog_decoder` which takes
  care of reading an elf file and generating several `.facts` files
  that represent the inital problem.
 
- `src/datalog/*.dl` contains the specification of the analyses in
  datalog.  It takes the basic facts and computes likely EAs, chunks
  of code, etc. The results are stored in `.csv` files.  These files
  can be compiled into `/bin/souffle_disasm`
 
- `src/disasm_driver.pl` is a prolog module that calls datalog_decored
  first, then it calls souffle (or souffle_disasm) and finally reads
  the results from the analysis and prints the assembler code. (this
  script can be called by executing `./bin/disasm`)

## Dependencies

- The project is prepared to be built with GTScons and has to be located
in the grammatech trunk directory.

- The analysis depends on souffle being installed, 
in particular the 64 bits version at https://github.com/cfallin/souffle.git
Update (Feb. 9th): The 64 bits version is now in the master branch https://github.com/souffle-lang/souffle/pull/569

- The pretty printer is (for now) written in prolog. It requires some prolog environment
to be installed (preferably SWI-prolog).

- The project contains a Makefile to compile without GTScons and without the grammatech
trunk directory, but it requires a folder `/standalone_compilation/` with the corresponding
libraries and header to be added to the project.

## Building souffle_disasm



`/trunk/datalog_disasm/build`

or for the standalone compilation:

```
cd src
make
```


## Running the analysis
Once souffle_disasm is built, we can run complete analysis on a file
by calling `/bin/disasm'`.
For example, we can run the analysis on one of the examples as
follows:

`cd bin` `./disasm ../examples/ex1/ex`

The script accepts the following parameters:

- `-debug` in addition to print what is considered to be code, it prints every instruction
  that has not been explicitly discarded and segments of assembler that have been discarded
  
- `-asm` generate reassembleable assembler that can be given to assembler directly.

- `-hints` generate a file `hints` with user hints (for csurf) in the
  same directory as the binary
  
- `-interpreted` this flag runs the souffle interpreter instead of the compiled version. It is mainly useful for development.

## Rewriting a project

The directory /bin contains several scripts to rewrite and test complete projects:

- `reassemble_and_test.sh` rebuilds a project using the compiler and compiler flags
specified in the enviroment variables CC and CFLAGS, rewrites the binary with 
`disasm` and run the project tests on the new binary.

- `CGC_reassemble_and_test.sh` does the analogous process but with CGC projects.
However, it receives the compiler and compiler flags as arguments


- `reassemble_no_rebuild.sh` rewrites a binary without trying to rebuild the project before
and without running tests later.

- `compare_with_melt.sh` runs the disassembler and generates user
hints these user hints are then compared to the IR resulting from
calling gtm using gtir_compare. It generates a file with the
differences and outputs filtered differences.


## Testing
The directory /tests also contains script for running extensive tests:

- `test_coreutils.sh` test coreutils with different compilers and optimization flags

- `test_real_examples.sh` test a list of real world applications
with different compilers and optimization flags. For now it assumes that the applications
are all at certain directory `real_world_examples`

- `test_CGC.sh` test a subset of the CGC programs with different compilers and optimization flags.

## Experimental Evaluation

We would like to perform an evaluation along the following dimensions:

Tools
- Datalog Disassembler
- GTx
- Ramblr

Benchmarks (× Compilers × Flags -- should include the versions used in the Ramblr paper)
- coreutils
- CGC binaries (a subset thereof)
- Real World binaries (we need a real methodology for how these were selected)
- Siemens programs

Metrics
- Runtime of the rewritten binaries
- Memory consumption of the rewritten binaries
- Size of the rewritten binaries (stripped)
- Runtime of the binary rewriter
- Memory consumption of the binary rewriter
- Functionality of the rewritten binaries (as measure by their test suites)
- Additional "precision" metrics (might be useful if we have GT-IRB)
    - symbolization
    - data vs. code location
    - function boundary identification

### Issues/TODOs

- Exception frames are ignored



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
