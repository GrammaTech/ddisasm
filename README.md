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
[GTIRB pretty printer](https://github.com/grammatech/gtirb-pprinter)
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
  being installed. At the moment we rely on the [1.5.1 souffle release](https://github.com/souffle-lang/souffle/releases/tag/1.5.1) configured with `--enable-64bit-domain
  --disable-provenance`.
  The easiest way to install the 1.5.1 souffle release is:
  ```
  git clone -b 1.5.1 https://github.com/souffle-lang/souffle
  ```
  followed by the standard [souffle build instructions](https://souffle-lang.github.io/docs/build/):
  ```
  cd souffle
  sh ./bootstrap
  ./configure --enable-64bit-domain --disable-provenance
  sudo make -j4 install
  ```

- [Capstone version 4.0.1](http://www.capstone-engine.org/)

- For printing assembler code the datalog disassembler requires the
  [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter)

- Ddisasm uses [libehp](https://git.zephyr-software.com/opensrc/libehp) to read exception
  information

## Building ddisasm
A C++17 compiler such as gcc 7 or clang 6 is required.

Boost (1.67 or later) and [GTIRB](https://github.com/grammatech/gtirb)
are required.

Use the following options to configure cmake:

- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.

- Normally CMake will find GTIRB automatically, but if it does not you
  can pass `-Dgtirb_DIR=<path-to-gtirb-build>`.

- By default ddisasm will download a copy of the boost libraries that
 it uses. If you want to use your local boost installation, use the
 flag: `-DDDISASM_USE_SYSTEM_BOOST=on`

- ddisasm can make use of GTIRB in static library form (instead of
 shared library form, the default) if you use the flag
 `-DDDISASM_BUILD_SHARED_LIBS=OFF`.

Once the dependencies are installed, you can configure and build as
follows:

```
$ cmake ./ -Bbuild
$ cd build
$ make
```
## Building ddisasm inside a Docker image

The directory [.ci](https://github.com/GrammaTech/ddisasm/tree/master/.ci) contains
several Docker files to build ddisasm under different OS. These docker
files assume that both GTIRB and gtirb-pprinter have been checked out
inside the ddisasm directory.

The steps to build ddisasm inside a ubuntu 16 image are:
```
git clone https://github.com/GrammaTech/ddisasm.git
cd ddisasm
git clone https://github.com/GrammaTech/gtirb.git
git clone https://github.com/GrammaTech/gtirb-pprinter.git
docker build -f .ci/Dockerfile.ubuntu16 -t ddisasm-ubuntu16 .
```

## Running the analysis

Once `ddisasm` is built, we can run complete analysis on a file by
calling `build/bin/ddisasm'`.  For example, we can run the analysis on one
of the examples as follows:

```
cd build/bin ./ddisasm ../../examples/ex1/ex --asm ex.s
```

Ddisasm accepts the following parameters:

`--help`
:   produce help message

`--sect arg (=.plt.got,.fini,.init,.plt,.text,)`
:   code sections to decode

`--data_sect arg (=.data,.rodata,.fini_array,.init_array,.data.rel.ro,.got.plt,.got,)`
:   data sections to consider

`--ir arg`
:   GTIRB output file

`--json arg`
:   GTIRB json output file

`--asm arg`
:   ASM output file

`--debug`
:   if the assembly code is printed, it is printed with debugging information

`--debug-dir arg`
:   location to write CSV files for debugging

-K [ --keep-functions ] arg
:   Print the given functions even if they are skipped by default (e.g. _start)

`--self-diagnose`
:   This option is useful for debugging. Use relocation information to emit a self diagnosis
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.


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

## AuxData generated by ddisasm

ddisasm generates the following AuxData tables:

| Key                  | Type                                                                                               | Purpose                                                                                                                                                                                                                |
|----------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| comments             | `std::map<gtirb::Offset, std::string>`                                                             | Per-instruction comments.                                                                                                                                                                                              |
| functionEntries      | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`                                                     | UUIDs of the blocks that are entry points of functions.                                                                                                                                                                |
| functionBlocks       | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`                                                     | UUIDs of the blocks that belong to each function.                                                                                                                                                                      |
| symbolForwarding     | `std::map<gtirb::UUID, gtirb::UUID>`                                                               | Map from symbols to other symbols. This table is used to forward symbols due to relocations or due to the use of plt and got tables.                                                                                   |
| encodings            | `std::map<gtirb::UUID, std::string>`                                                               | Map from (typed) data objects to the encoding of the data, expressed as a `std::string` containing an assembler encoding specifier: "string", "uleb128" or "sleb128".                                                  |
| elfSectionProperties | `std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>>`                                            | Map from section UUIDs to tuples with the ELF section types and flags.                                                                                                                                                 |
| cfiDirectives        | `std::map<gtirb::Offset, std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>` | Map from Offsets to vector of cfi directives. A cfi directive contains: a string describing the directive, a vector of numeric arguments, and an optional symbolic argument (represented with the UUID of the symbol). |
| libraries            | `std::vector<std::string>`                                                                         | Names of the libraries that are needed.                                                                                                                                                                                |
| libraryPaths         | `std::vector<std::string>`                                                                         | Paths contained in the rpath of the binary.                                                                                                                                                                            |

## Some References

1. [Datalog Disassembly](https://arxiv.org/abs/1906.03969)

2. [Souffle](https://github.com/souffle-lang/souffle)

3. [Capstone disassembler](http://www.capstone-engine.org/)

4. [Control Flow Integrity for COTS Binaries](http://seclab.cs.sunysb.edu/seclab/pubs/usenix13.pdf)

5. [Alias analysis for Assembly](http://reports-archive.adm.cs.cmu.edu/anon/anon/usr/ftp/2006/CMU-CS-06-180R.pdf)

6. [Reassembleable Disassembling](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-wang-shuai.pdf)

7. [Ramblr: Making reassembly great again](https://pdfs.semanticscholar.org/dcf5/dc7e6ae2614dd0079b851e3f292148366ca8.pdf)

8. [An In-Depth Analysis of Disassembly on Full-Scale x86/x64 Binaries](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_andriesse.pdf)

9. [Binary Code is Not Easy](https://dl.acm.org/citation.cfm?id=2931047)
