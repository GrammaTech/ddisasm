% DDISASM(1) DATALOG DISASSEMBLER
% GrammaTech Inc
% September 2018

# NAME

ddisasm - disassemble a binary and generate assembly code that is ready for reassembly.

# SYNOPSIS

**ddisasm** *BINARY*  [*options*...]

# DESCRIPTION

The datalog disassembler **ddisasm** executable disassembles a binary
*BINARY* and produces GTIRB, an intermediate representation for binary
analysis (See [GTIRB](https://github.com/grammatech/gtirb)).
**ddisasm** integrates the [GTIRB pretty
printer](https://github.com/grammatech/gtirb-pprinter) which may then be
used to pretty print the GTIRB to reassembleable assembly code.

Currently `ddisasm` supports x64 executables in ELF format.


# OPTIONS

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
:   This option is useful for debugging. Use relocation information to emit a self diagnose
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.

`-F [ --skip-function-analysis ]`
:   Skip additional analyses to compute more precise function boundaries.

`-j [ --threads ]`
:   Number of cores to use. It is set to the number of cores in the machine by default.

# EXAMPLES

**ddisasm** ./examples/ex1/ex

Disassemble binary `ex` and print the assembly result in stdout

**ddisasm** ex --asm ex.s

Disassemble binary `ex` and print the assembly result in file `ex.s`

**ddisasm** ex --ir ex.gtirb

Disassemble binary `ex` and write its GTIRB intermediate represention
in `ex.gtirb`

**ddisasm** ex --asm ex.s --debug

Disassemble binary `ex` and print the assembly code with debugging information in file `ex.s`


# SEE ALSO

**gtirb-pprinter** (1).
The `gtirb-pprinter` prints gtirb files as assembly code.
