# 1.9.1 (Unreleased)

* Fix a hang due to incorrect jump-table boundaries inferred from irrelevant register correlations to the index register
* Requires gtirb >=2.2.0
* Improved code inference:
    - Do not miss code after literal pools.
    - Switch decode mode if invalid instruction found in ARM.
    - Fixed bug in pointers to string data blocks.
    - Restrict padding blocks so they do not share instructions with code blocks.
    - Start a new block if we transition from padding to not padding
      or from not padding to padding.
    - Change the type of several heuristics from "simple" to "proportional"
    - Additional heuristic: Simple string literals in literal pools
    - Additional heuristic: Function beginning pattern with push/adjust-sp as plausible instruction sequence
* Fix bug that led to string data blocks potentially overlapping code blocks.
* Fix bug that resulted in integral symbols on ISAs other than x64 (ARM and x86).
* Fix symbolization bug of ADR instructions in ARM32 that refer to code.
* Fix bug in PE code inference that could lead to the whole .text section being
  declared invalid if a data directory was attached to the end of the section.
* Add alignments to data blocks that require alignment even within data
  sections
* Fix 16-Thumb STM instructions considered to be invalid if the same register
  is used in reglist and register operands with writeback enabled.
* Fixed bug that could result in missed symbolic expressions with TLS variables for `local-executable` TLS model
* Fix bug that caused assembling error due to wrong `symbol_minus_symbol`
  for lsda entries with references to the end of `.gcc_except_table`
* Generate alignments for function entry blocks depending on address

# 1.9.0

* Stop generating debian metapackages and packages with the version attached
  to the package name. Updates in the apt-repository now support multiple
  package versions and upgrading `ddisasm` with `apt-get upgrade`.
* Improve def-use and value-reg stack analysis to consider push and pop
  instructions. These changes also fix a couple of bugs in the stack variable
  propagation.
* Update LIEF to 0.13.2
* No longer consider `_x86.get_pc_thunk*` functions as ABI-intrinsic; this
  means `_copy` is not appended to the original symbol, and a symbol forwarding
  entry is not created.
* Fix handling of BLR instruction in ARM64.
* Fix size access of LDR instruction in ARM64.
* Extend value_reg analysis to support memory loads using a register with
  constant address.
* Refactor the code inference point system. Decouple heuristics from their weights.
  Heuristic weights can now be modified by providing user hints.
* Generate GOT, PAGE and GOT, OFST symbolic expression attributes for split
  .got loads on MIPS.
* Correct symbol_minus_symbol in lsda entries with a reference to the end of `.gcc_except_table`: add `boundary_sym_expr` for such reference
* Add `ElfSoname` aux-data for `SONAME` dynamic-section entry
* Requires gtirb >=2.1.0
* Track values of registers R8B - R15B on x86-64, which are in some cases needed for inferring jump table boundaries.
* Infer jump table boundaries from comparisons of registers correlated to the index register.
* Relax constraints for inferring jump table boundaries from comparisons of indirect operands
* Fix bug where a relative jump table starting with consecutive zero offsets was truncated at the first non-zero value.
* Add alignment for x86-64 instructions that require explicitly aligned memory
  (e.g., some SIMD instructions)
* Update capstone version from 4.0.1 to 5.0.1
* Avoid generating `_start` symbol when the entry-point address is not a code block.

# 1.8.0

* Prefer LOCAL symbols over GLOBAL ones when selecting symbols for symbolic
  expressions for ISAs other than MIPS.
* Support GTIRB sections with holes (byte intervals only covering part of the section).
* Use pre-existing code blocks as hints when disassembling a RAW binary.
* Better data access computation for MIPS binaries.
* Detect incremental linking regions in PE binaries.
* Create elfStackSize and elfStackExec auxdata from ELF PT_GNU_STACK segments.
* In PE binaries, every exported code symbol is considered a function entry.
* Fixed bug where `elfSymbolTabIdxInfo` aux data could refer to non-existent UUIDs.
* Fixed unrecognized `tls_get_addr` pattern that could result in missed
  symbolic expressions.
* Binaries with zero-sized `OBJECT` symbols no longer produce missing code
  blocks.
* `$t` symbols in ARM binaries now force creation of Thumb-mode code blocks.
* In PE binaries, duplicate imports no longer create duplicate symbols.
* Added pattern to match missed symbolic data in pointer arrays.
* Fix symbols associated to functions (Auxdata functionNames) for PE binaries
  when Ddisasm is run with option `-F`.
* Requires gtirb >=2.0.0, gtirb-pprinter >=2.0.0

# 1.7.0
* Update code inference to use weighted interval scheduling to resolve blocks;
  this improves code inference results, especially on ARM.
* ARM: Discover unreferenced code blocks occurring after literal pools.
* Refactored CFG inference. It now infers more kinds of indirect calls and
  and branches using value analysis, data accesses, and relocations.
* ELF: Infer `SHARED` or `PIE` for `DYN` binary type
* ELF: Generate `elfDynamicInit` and `elfDynamicFini` auxdata

# 1.6.0
* ARM: Improve code inference using unwind information from .ARM.exidx section
* Replace symbolic expression attributes with composable labels.
* ddisasm output now displays runtimes of "load", "compute", and "transform"
  phases of each analysis pass
* Add known_block and impossible_block passes to code inference.
* Various ARM32 code inference improvements.
* Various command-line options now apply to all datalog passes:
  * `--debug-dir` creates subdirectories for each datalog pass
  * `--interpreter` argument now specifies the source code repository's root
    directory, defaults to the current working directory, and enables the
    interpreter for all datalog passes
  * `--profile` specifies a directory name where profiles for each datalog pass
    is written
  * Entries in files provided to `--hints` should namespace relation names using
    the name of the analysis pass, e.g., `disassembly.invalid`.
  * `--with-souffle-relations` keeps relations from all passes; entries in the
    `souffleFacts` and `souffleOutputs` auxdata are now namespaced
    with the name of the analysis pass, e.g., `disassembly.block_points`.
* Add support for x86-32 dynamic TLS.
* Improve IFUNC symbolic expression symbol selection.
* Several refactorings towards spliting code inference and symbolization.
* Refactor ELF symbol reading.
* Add "overlay" AuxData table.
* Update Souffle to version 2.4.
* Add cmake option `DDISASM_GENERATE_MANY` to use Souffle's `--generate-many`
  code generation option; this should yield much faster incremental build times
  for ddisasm.
* Utilize Souffle's feature to prune intermediate relations to reduce ddisasm's
  peak memory usage; processing large binaries can use up to ~20% less memory.
* Update LIEF to 0.13.0.
* Add Linux Python package for ddisasm.

# 1.5.6
* Discover ARM Thumb blocks at section start in stripped binaries.
* Bugfix for undefined TLS symbol relocations.
* Add ARM `HLT` and `TRAP` instruction support.
* Bugfix for aliased copy-relocations.
* Bugfix to avoid propagating synchronous accesses across symbols.
* Add build option for compiled Souffle profile generation.
* Improved x86-64 dynamic TLS support.
* Various logic improvements for GLIBC rewriting support.

# 1.5.5
* Update generated `elfSymbolVersions` auxdata.
* Add "--ignore-errors" argument.
* Update LIEF to version 0.12.3.

# 1.5.4
* Add PE32 Safe Structured Exception Handling (SAFESEH) support.
* Update LIEF to version 0.12.1.
* Update Souffle to version 2.3.
* Ubuntu 18 and gcc7 are no longer supported
* ARM64 support improvements:
  * Handle single-byte jump tables where the value should be interpreted as a
    signed difference.
  * Prevent generation of incorrect :lo12: attributes in post-index operands.
* Add "--hints" argument.

# 1.5.3
* Rename `elfSectionIndex` to `sectionIndex`, and `elfSectionProperties` to
  `sectionProperties`, and remove `peSectionProperties`.
* Refactor `section_complete`: add `section_property`, and rename `section_complete`
  to `section`, and `section` to `loaded_section`.
* Ensure ddisasm --version always reports a commit hash.
* Improve handling of unnamed relocations for libraries and object files.
* Improvements to jump table detection.
* ARM64 support improvements:
  * Support symbolization of split loads separated by jump tables or temporary
    stack storage.
  * Fix disassembling tbz and tbnz branch instructions.
  * Fix value tracking of special registers (FP, LR, SP).
  * Eliminate warnings generated by SYS instructions.
  * Fix disassembling stripped ARM64 binaries.
* Release support for ARM32 and MIPS32 binaries.
* Optimizations to improve performance and reduce memory usage.
* Require GrammaTech's Capstone fork, >5.0.0.
* Add "--profile" argument.

# 1.5.2
* Add ELF x86_64 .o support.
* Add static archive support.
* Fix a bug with ELF file parsing that could generate failed "unknown binding
  in elfSymbolInfo" assertions.
* Infer "main" function in ARM64 binaries.

# 1.5.1
* Use dedicated symbolic expression attributes.

# 1.5.0
* Support Souffle interpreter for development.
* Add support for loading existing GTIRB files.

# 1.4.0

* Add PE support.
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
