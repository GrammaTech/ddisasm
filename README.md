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


## Dependencies

ddisasm uses C++17, and requires a compiler which supports
that standard such as gcc 7, clang 6, or MSVC 2017.

To build and install ddisasm, the following requirements
should be installed:

- [gtirb](https://github.com/grammatech/gtirb)
- [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter)
- [Capstone](http://www.capstone-engine.org/), version 4.0.1 or later
- [Souffle](https://souffle-lang.github.io), version 1.7.0 or higher
  - Must be configured with support for 64 bit numbers (via `--enable-64bit-domain` during configuration)
- [libehp](https://git.zephyr-software.com/opensrc/libehp), version 1.0.0 or higher
- [LIEF](https://lief.quarkslab.com/), version 0.9.0 or higher

Note that these versions are newer than what your package manager may provide
by default: This is true on Ubuntu 18, Debian 10, and others. Prefer building
these dependencies from sources to avoid versioning problems.

## Building ddisasm
Use the following options to configure cmake:

- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.

- Normally CMake will find GTIRB automatically, but if it does not you
  can pass `-Dgtirb_DIR=<path-to-gtirb-build>`.

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

The directory [.ci](https://github.com/GrammaTech/ddisasm/tree/master/.ci)
contains several Docker files to build ddisasm under different OS and compiler.
These docker files assume that GTIRB, gtirb-pprinter and libehp have been
checked out inside the ddisasm directory.

The steps to build ddisasm inside a ubuntu 16 image using clang are:
```
git clone https://github.com/GrammaTech/ddisasm.git
cd ddisasm
git clone https://github.com/GrammaTech/gtirb.git
git clone https://github.com/GrammaTech/gtirb-pprinter.git
git clone https://git.zephyr-software.com/opensrc/libehp
docker build -f .ci/Dockerfile.ubuntu16-clang -t ddisasm-ubuntu16-clang .
```

## Running the analysis

Once `ddisasm` is built, we can run complete analysis on a file by
calling `build/bin/ddisasm'`.  For example, we can run the analysis on one
of the examples as follows:

```
cd build/bin && ./ddisasm ../../examples/ex1/ex --asm ex.s
```

Ddisasm accepts the following parameters:

`--help`
:   produce help message

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

`-K [ --keep-functions ] arg`
:   Print the given functions even if they are skipped by default (e.g. _start)

`--self-diagnose`
:   This option is useful for debugging. Use relocation information to emit a self diagnosis
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.

`-F [ --skip-function-analysis ]`
:   Skip additional analyses to compute more precise function boundaries.

`-j [ --threads ]`
:   Number of cores to use. It is set to the number of cores in the machine by default.

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

| Key                     | Type                                                                                               | Purpose                                                                                                                                                                                                                |
|-------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| comments                | `std::map<gtirb::Offset, std::string>`                                                             | Per-instruction comments.                                                                                                                                                                                              |
| functionEntries         | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`                                                     | UUIDs of the blocks that are entry points of functions.                                                                                                                                                                |
| functionBlocks          | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`                                                     | UUIDs of the blocks that belong to each function.                                                                                                                                                                      |
| symbolForwarding        | `std::map<gtirb::UUID, gtirb::UUID>`                                                               | Map from symbols to other symbols. This table is used to forward symbols due to relocations or due to the use of plt and got tables.                                                                                   |
| encodings               | `std::map<gtirb::UUID, std::string>`                                                               | Map from (typed) data objects to the encoding of the data, expressed as a `std::string` containing an assembler encoding specifier: "string", "uleb128" or "sleb128".                                                  |
| elfSectionProperties    | `std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>>`                                            | Map from section UUIDs to tuples with the ELF section types and flags.                                                                                                                                                 |
| cfiDirectives           | `std::map<gtirb::Offset, std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>` | Map from Offsets to vector of cfi directives. A cfi directive contains: a string describing the directive, a vector of numeric arguments, and an optional symbolic argument (represented with the UUID of the symbol). |
| libraries               | `std::vector<std::string>`                                                                         | Names of the libraries that are needed.                                                                                                                                                                                |
| libraryPaths            | `std::vector<std::string>`                                                                         | Paths contained in the rpath of the binary.                                                                                                                                                                            |
| padding                 | `std::map<gtirb::Offset, uint64_t>`                                                                | Offset where there is padding and the length of the padding in bytes.                                                                                                                                                 |
| SCCs                    | `std::map<gtirb::UUID, int64_t>`                                                                   | The intra-procedural SCC identifier of each block                                                                                                                                                                      |
| symbolicExpressionSizes | `std::map<gtirb::Offset, uint64_t>`                                                                | Map from an Offset of a symbolic expression in a ByteInterval to its extent, a size in bytes.                                                                                                                          |

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
