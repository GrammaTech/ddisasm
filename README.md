Datalog Disassembly
===================

DDisasm is a *fast* disassembler which is *accurate* enough for the
resulting assembly code to be reassembled.  DDisasm is implemented
using the datalog ([souffle](https://github.com/souffle-lang/souffle))
declarative logic programming language to compile disassembly rules
and heuristics.  The disassembler first parses ELF/PE file information
and decodes a superset of possible instructions to create an initial
set of datalog facts.  These facts are analyzed to identify *code
location*, *symbolization*, and *function boundaries*.  The results of
this analysis, a refined set of datalog facts, are then translated to
the [GTIRB](https://github.com/grammatech/gtirb) intermediate
representation for binary analysis and reverse engineering.  The
[GTIRB pretty printer](https://github.com/grammatech/gtirb-pprinter)
may then be used to pretty print the GTIRB to reassemblable assembly
code.

## Binary Support

Binary formats:

 - ELF (Linux)
 - PE  (Windows)

Instruction Set Architectures (ISAs):

-  x86_32
-  x86_64
-  ARM32
-  ARM64
-  MIPS32

## Getting Started

You can run a prebuilt version of Ddisasm using Docker:

```bash
docker pull grammatech/ddisasm:latest
```

Ddisasm can be used to disassemble a binary into the [GTIRB](https://github.com/grammatech/gtirb) representation.
We can try it with one of the examples included in the repository.

First, start the Ddisasm docker container:
```bash
docker run -v $PWD/examples:/examples -it grammatech/ddisasm:latest
```

Within the Docker container, let us build one of the examples:

```bash
apt update && apt install gcc -y
cd /examples/ex1
gcc ex.c -o ex
```

Now we can proceed to disassemble the binary:

```bash
ddisasm ex --ir ex.gtirb
```

Once you have the GTIRB representation, you can make programmatic changes to the
binary using [GTIRB](https://github.com/grammatech/gtirb) or [gtirb-rewriting](https://github.com/grammatech/gtirb-rewriting).

Then, you can use [gtirb-pprinter](https://github.com/grammatech/gtirb-pprinter) (included in the Docker image) to produce
a new version of the binary:

```
gtirb-pprinter ex.gtirb -b ex_rewritten
```

Internally, `gtirb-pprinter` will generate an assembly file and invoke the compiler/assembler (e.g. gcc)
to produce a new binary. `gtirb-pprinter` will take care or generating all the necessary command line
options to generate a new binary, including compilation options, library dependencies, or version linker scripts.

You can also use `gtirb-pprinter` to generate an assembly listing for manual modification:
```bash
gtirb-pprinter ex.gtirb --asm ex.s
```

This assembly listing can then be manually recompiled:
```bash
gcc -nostartfiles ex.s -o ex_rewritten
```

Please take a look at our [documentation](https://grammatech.github.io/ddisasm/) for additional information.

## [Documentation](https://grammatech.github.io/ddisasm/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## External Contributors

 * Programming Language Group, The University of Sydney: Initial support for ARM64.
 * Github user gogo2464: Documentation refactoring.

## Cite

1. [Datalog Disassembly](https://www.usenix.org/conference/usenixsecurity20/presentation/flores-montoya)

```
@inproceedings {flores-montoya2020,
    author = {Antonio Flores-Montoya and Eric Schulte},
    title = {Datalog Disassembly},
    booktitle = {29th USENIX Security Symposium (USENIX Security 20)},
    year = {2020},
    isbn = {978-1-939133-17-5},
    pages = {1075--1092},
    url = {https://www.usenix.org/conference/usenixsecurity20/presentation/flores-montoya},
    publisher = {USENIX Association},
    month = aug,
}
```

2. [GTIRB](https://arxiv.org/abs/1907.02859)

```
@misc{schulte2020gtirb,
    title={GTIRB: Intermediate Representation for Binaries},
    author={Eric Schulte and Jonathan Dorn and Antonio Flores-Montoya and Aaron Ballman and Tom Johnson},
    year={2020},
    eprint={1907.02859},
    archivePrefix={arXiv},
    primaryClass={cs.PL}
}
```
