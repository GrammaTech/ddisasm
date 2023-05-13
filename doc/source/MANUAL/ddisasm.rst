% DDISASM(1) DATALOG DISASSEMBLER
% GrammaTech Inc
% September 2018

NAME
=========

ddisasm - disassemble a binary and generate assembly code that is ready for reassembly.

SYNOPSIS
============

**ddisasm** *BINARY*  [*options*...]

DESCRIPTION
============


The datalog disassembler **ddisasm** executable disassembles a binary
*BINARY* and produces GTIRB, an intermediate representation for binary
analysis (See [GTIRB](https://github.com/grammatech/gtirb)).
**ddisasm** integrates the [GTIRB pretty
printer](https://github.com/grammatech/gtirb-pprinter) which may then be
used to pretty print the GTIRB to reassembleable assembly code.

Currently `ddisasm` supports x64 executables in ELF format.


OPTIONS
==========

Ddisasm accepts the following parameters:

.. code-block:: bash

    --help
    
:   produce help message

.. code-block:: bash

    --ir arg
    
:   GTIRB output file

.. code-block:: bash

    --json arg
    
:   GTIRB json output file

.. code-block:: bash

    --asm arg
    
:   ASM output file

.. code-block:: bash

    --debug
    
:   if the assembly code is printed, it is printed with debugging information

.. code-block:: bash

    --debug-dir arg
    
:   location to write CSV files for debugging

.. code-block:: bash

    -K [ --keep-functions ] arg
    
:   Print the given functions even if they are skipped by default (e.g. _start)

.. code-block:: bash

    --self-diagnose
    
:   This option is useful for debugging. Use relocation information to emit a self diagnose
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.
    
.. code-block:: bash

     -F [ --skip-function-analysis ]
     
:   Skip additional analyses to compute more precise function boundaries.

.. code-block:: bash

    -j [ --threads ]
    
:   Number of cores to use. It is set to the number of cores in the machine by default.

EXAMPLES
==========

.. code-block:: bash

    ./examples/ex1/ex

Disassemble binary `ex` and print the assembly result in stdout

.. code-block:: bash

    ex --asm ex.s

Disassemble binary `ex` and print the assembly result in file `ex.s`

.. code-block:: bash

    ex --ir ex.gtirb

Disassemble binary `ex` and write its GTIRB intermediate represention
in `ex.gtirb`

.. code-block:: bash

    ex --asm ex.s --debug

Disassemble binary `ex` and print the assembly code with debugging information in file `ex.s`


EE ALSO
=============

**gtirb-pprinter** (1).
The `gtirb-pprinter` prints gtirb files as assembly code.
