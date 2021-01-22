
* Support ELF x64 static binaries
* Add preliminary x86-32 support.

# 1.3.0

* Populate GTIRB symbolic expression attributes.
* Update to souffle 2.0.2.
* Populate all allocated ELF sections.

# 1.2.0

* Register value analysis can track values through the stack.
* Refactor `gtirb-decoder` for more versatile loading of GTIRB.

# 1.1.1

* Restructure gtirb-to-datalog into `gtirb-decoder` component.
* Move `ddisasm_main.cpp` to `Main.cpp`.
* Move `GtirbModuleDisassembler.cpp` to `Disassembler.cpp`.

# 1.1.0

* Added preliminary ARM64 support.
  Contributed by the Programming Language Group, University of Sydney.

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
