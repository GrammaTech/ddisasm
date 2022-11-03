Datalog Disassembly
===================

DDisasm is a *fast* disassembler which is *accurate* enough for the
resulting assembly code to be reassembled.  DDisasm is implemented
using the datalog ([souffle](https://github.com/souffle-lang/souffle))
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

Use the [grammatech/ddisasm](https://hub.docker.com/r/grammatech/ddisasm)
Docker image to try out `ddisasm` quickly.

ddisasm supports disassembling ELF and PE binary formats on x86_32, x86_64,
ARM32, ARM64, and MIPS32 architectures.

## Usage

ddisasm can be used to disassemble an ELF binary:

```
ddisasm examples/ex1/ex --asm ex.s
```

The generated assembly can then be rebuilt with gcc:

```
gcc ex.s -o ex_rewritten
```

## Installing

Pre-built packages are available to install ddisasm on Windows or Ubuntu.

See the [GTIRB readme](https://github.com/GrammaTech/gtirb/#installing) for details.

## Dependencies

ddisasm uses C++17, and requires a compiler which supports
that standard such as gcc 9, clang 6, or MSVC 2017.

To build ddisasm from source, the following requirements should be installed:

- [gtirb](https://github.com/grammatech/gtirb)
- [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter)
- [Capstone](http://www.capstone-engine.org/), version 5.0.0 or later
  - 5.x is not yet released by the Capstone team.
  - GrammaTech builds and tests using the [GrammaTech/capstone](https://github.com/GrammaTech/capstone) fork.
- [Souffle](https://souffle-lang.github.io), version 2.3
  - Must be configured with support for 64 bit numbers (via `-DSOUFFLE_DOMAIN_64BIT=1` during configuration)
- [libehp](https://git.zephyr-software.com/opensrc/libehp), version 1.0.0 or higher
- [LIEF](https://lief.quarkslab.com/), version 0.12.3 or higher

Note that these versions are newer than what your package manager may provide
by default: This is true on Ubuntu 18, Debian 10, and others. Prefer building
these dependencies from sources to avoid versioning problems. Alternatively,
you can use the GrammaTech PPA to get the correct versions of the dependencies.
See the [GTIRB readme](https://github.com/GrammaTech/gtirb/#installing) for
instructions on using the GrammaTech PPA.

## Building ddisasm
Use the following options to configure cmake:

- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.

- You can tell CMake about the paths to its dependencies as follows:

| Option               | Description                                 |
|----------------------|---------------------------------------------|
| `gtirb_DIR`          | Path to the GTIRB build directory.          |
| `gtirb_pprinter_DIR` | Path to the gtirb-pprinter build directory. |
| `LIEF_DIR`           | Path to the LIEF build directory.           |

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

### Debug build options

One can selectively turn off ddisasm's various architecture support modules to speed up compilation time during development.
For example:
```
$ cmake ./ -Bbuild -DDDISASM_ARM_64=OFF -DDDISASM_X86_32=OFF
```
will deactivate ARM_64 and X86_32 support.

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

`--hints arg`
:   location of user-provided hints file

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

`-I [ --interpreter ] arg`
:   Execute the Souffle interpreter with the specified source file.

`-L [ --library-dir ] arg`
:   Specify the search directory for the Souffle interpreter to locate functor libraries.

`--profile arg`
:   Execute the Souffle profiler to generate the specified profile log file.

## Testing

To run the test suite, run:

```
cd build && PATH=$(pwd)/bin:$PATH ctest
```

## Providing User Hints

A user can provide a file with user hints to guide and overcome limitations in the current ddisasm
implementation. User hints are simply datalog facts that are added to the database before running
the Datalog program. Datalog hints are provided in tab-separated .csv format where the first field
is the predicate name and subsequent fields are the fact field values to be added.

For example
```
invalid 0x100 definitely_not_code
```
will add a fact `invalid(0x100,"definitely_not_code")` to the Datalog database.
The fields need to be separated by tabs '\t'.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## External Contributors

 * Programming Language Group, The University of Sydney: Initial support for ARM64.

## AuxData

See [doc/AuxData.md](doc/AuxData.md)

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
