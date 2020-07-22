# 1.1.1

* Restructure gtirb-to-datalog into `gtirb-decoder` component.
* Move `ddisasm_main.cpp` to `Main.cpp`.
* Move `GtirbModuleDisassembler.cpp` to `Disassembler.cpp`.

# 1.1.0

* Added preliminary ARM64 support.

# 1.0.1

* Populate libraries and libraryPaths aux data tables.
* Allow using '-' as an output alias for stdout.
* Refactor binary object parsing into gtirb-builder.
* Fix performance bug for large data sections.
* Aggressive propagation for relative jump tables.
* Use defs through indirect jumps.
* Create data blocks spanning multiple bytes.

# 1.0.0

* Added --version flag, initial version is 1.0.0
