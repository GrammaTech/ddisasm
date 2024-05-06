# Command-Line options

Ddisasm accepts the following options:

`--help`
:   produce help message

`--version`
:   display ddisasm version

`--ir arg`
:   GTIRB output file

`--json arg`
:   GTIRB json output file

`--asm arg`
:   ASM output file

`--debug`
:   generate GTIRB file with debugging information

`--debug-dir arg`
:   location to write CSV files for debugging

`--hints arg`
:   location of user-provided hints file

`--input-file arg`
:   File to disasemble

`--ignore-errors`
:   Return success even if there are disassembly errors.

`-K [ --keep-functions ] arg`
:   Print the given functions even if they are skipped by default (e.g. _start)

`--self-diagnose`
:   This option is useful for debugging. Use relocation information to emit a self diagnosis
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.

`-F [ --skip-function-analysis ]`
:   Skip additional analyses to compute more precise function boundaries.

`--with-souffle-relations`
:   Package facts/output relations into an AuxData table.

`--no-cfi-directives`
:   Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame
(this functionality is experimental and does not produce reliable results).

`-j [ --threads ]`
:   Number of cores to use.

`-n [ --no-analysis ]`
:   Do not perform disassembly. This option only parses/loads the binary object into GTIRB.

`-I [ --interpreter ] arg`
:   Execute the Souffle interpreter with the specified source directory.

`-L [ --library-dir ] arg`
:   Specify the search directory for the Souffle interpreter to locate functor libraries.

`--profile arg`
:   Generate Souffle profiling information in the specified directory.
