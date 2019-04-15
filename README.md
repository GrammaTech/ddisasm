Datalog Disassembly
===================

A *fast* disassembler which is *accurate* enough for the resulting
assembly code to be reassembled.  The disassembler implemented using
the datalog ([souffle](https://github.com/souffle-lang/souffle))
declarative logic programming language to compile disassembly rules
and heuristics.  The disassembler first parses ELF file information
and decodes a superset of possible instructions to create an initial
set of datalog facts.  These facts are analyzed to identify *code
location*, *symbolization*, and *function boundaries*.  The results of
this analysis, a refined set of datalog facts, are then translated to
the [GTIRB](https://github.com/grammatech/gtirb) intermediate
representation for binary analysis and reverse engineering.  The
[GTIRB pretty printer](https://github.com/grammatech/gtirb-pprinte)
may then be used to pretty print the GTIRB to reassemblable assembly
code.


## Introduction

The analysis contains two parts:

- The C++ files take care of reading an elf file and generating facts
  that represent all the information contained in the binary.

- `src/datalog/*.dl` contains the specification of the analyses in
  datalog.  It takes the basic facts and computes likely EAs, chunks
  of code, etc. The results are represented in GTIRB or can be printed
  to assembler code using the gtirb-pprinter.


## Dependencies

- [GTIRB](https://github.com/grammatech/gtirb)

- The analysis depends on [souffle](https://github.com/souffle-lang)
  being installed. Configure souffle with `--enable-64bit-domain
  --disable-provenance`.

- For printing assembler code the datalog disassembler requires the
  [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter)


## Building ddisasm
A C++17 compiler such as gcc 7 or clang 6 is required.

Boost (1.67 or later) and [GTIRB](https://github.com/grammatech/gtirb)
are required.

Use the following options to configure cmake:

- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.

- Normally CMake will find GTIRB automatically, but if it does not you
  can pass `-Dgtirb_DIR=<path-to-gtirb-build>`.

Once the dependencies are installed, you can configure and build as
follows:

```
$ cmake ./ -Bbuild
$ cd build
$ make
```


## Running the analysis

Once `ddisasm` is built, we can run complete analysis on a file by
calling `/bin/ddisasm'`.  For example, we can run the analysis on one
of the examples as follows:

```
cd build/bin ./ddisasm ../../examples/ex1/ex --asm ex.s
```

The script accepts the following parameters:

`--help`
:   produce help message

`--sect arg (=.plt.got,.fini,.init,.plt,.text,)`
:   code sections to decode

`--data_sect arg (=.data,.rodata,.fini_array,.init_array,.data.rel.ro,.got.plt,.got,)`
:   data sections to consider

`--ir arg`
:   GTIRB output file

`--asm arg`
:   ASM output file

`--debug`
:   if the assembly code is printed, it is printed with debugging information

`--debug-dir arg`
:   location to write CSV files for debugging


## Rewriting a project

The directory tests/ contains the script `reassemble_and_test.sh` to
rewrite and test a complete project. `reassemble_and_test.sh` rebuilds
a project using the compiler and compiler flags specified in the
enviroment variables CC and CFLAGS (`make -e`), rewrites the binary
and run the project tests on the new binary.

We can rewrite ex1 as follows:

```
cd examples/ex1
make
ddisasm ex --asm ex.s
gcc ex.s -o ex_rewritten
```

## Testing

The directory `tests/` also contains a script `test_small.sh` for
rewriting the examples in `/examples` with different compilers and
optimization flags.


## Contributing

Please read the [DDisasm Code of Conduct](CODE_OF_CONDUCT.md).

Please follow the Code Requirements in
[gtirb/CONTRIBUTING](https://github.com/GrammaTech/gtirb/blob/master/CONTRIBUTING.md#code-requirements).


## Some References

1. [Souffle](https://github.com/souffle-lang/souffle)

2. [Capstone disassembler](http://www.capstone-engine.org/)

3. [Control Flow Integrity for COTS Binaries](http://stonecat/repos/reading/papers/12313-sec13-paper_zhang.pdf)

4. [Alias analysis for Assembly](http://reports-archive.adm.cs.cmu.edu/anon/anon/usr/ftp/2006/CMU-CS-06-180R.pdf)

5. [Reassembleable Disassembling](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-wang-shuai.pdf)

6. [Ramblr: Making disassembly great again](https://pdfs.semanticscholar.org/dcf5/dc7e6ae2614dd0079b851e3f292148366ca8.pdf)

7. [An In-Depth Analysis of Disassembly on Full-Scale x86/x64 Binaries](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_andriesse.pdf)

8. [Binary Code is Not Easy](http://delivery.acm.org/10.1145/2940000/2931047/p24-meng.pdf?ip=98.159.213.242&id=2931047&acc=CHORUS&key=4D4702B0C3E38B35%2E4D4702B0C3E38B35%2E4D4702B0C3E38B35%2E6D218144511F3437&__acm__=1539001930_dedfe0a1aa0c9bf006dbe0874ff74722)
