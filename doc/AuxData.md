GTIRB [Auxiliary Data][1] (`AuxData`) tables are a value-store for arbitrary
user-defined analysis data. GTIRB defines a number of `AuxData` tables with
stable schemata that are recommended for all GTIRB users as [Sanctioned][2]
tables and also a set of tables under consideration for standardization as
[Provisional][3].

_Note that all unsanctioned tables are considered unstable and their schemata
may change between minor releases._

Ddisasm generates the following `sanctioned`, `provisional`, and `unsanctioned`
tables:

[1]: https://grammatech.github.io/gtirb/md__aux_data.html
[2]: https://grammatech.github.io/gtirb/md__aux_data.html#sanctioned-auxdata-tables
[3]: https://grammatech.github.io/gtirb/md__aux_data.html#provisional-auxdata-tables

## General

## ddisasmVersion

`unsanctioned`

|       |                                                        |
|------:|--------------------------------------------------------|
|  Name | **ddisasmVersion**                                     |
|  Type | `std::string`                                          |
| Value | The version of ddisasm used to produce the GTIRB file. |

For example, `1.5.3 (8533031c 2022-03-31) X64` represents version `1.5.3`
compiled on commit `8533031c` with support for the `X64` ISA.

## binaryType

`unsanctioned`

|       |                                    |
|------:|------------------------------------|
|  Name | **binaryType**                     |
|  Type | `std::vector<std::string>`         |
| Value | A list of binary type descriptors. |

ELF binaries have either a `DYN` (PIE) or `EXEC` entry. PE binaries have either
a `DLL` or `EXE` entry and optionally a [subsystem][SUBSYSTEM] descriptor (e.g.
`WINDOWS_GUI`).

[SUBSYSTEM]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem

## archInfo

`unsanctioned`

|       |                                              |
|------:|----------------------------------------------|
|  Name | **archInfo**                                 |
|  Type | `std::vector<std::string>`                   |
| Value | A list of detailed architecture information. |

_Note that this is currently only used for ARM32 to indicate the binary is for a `Microcontroller`._

## comments

`sanctioned`

|       |                                        |
|------:|----------------------------------------|
|  Name | **comments**                           |
|  Type | `std::map<gtirb::Offset, std::string>` |
| Value | Per-instruction comments.              |

Comments are used to bind additional analysis details and debugging information
to instructions. *See the `--debug` command line flag.*

## padding

`sanctioned`

|       |                                                                      |
|------:|----------------------------------------------------------------------|
|  Name | **padding**                                                          |
|  Type | `std::map<gtirb::Offset, uint64_t>`                                  |
| Value | Offset of padding in a ByteInterval and the padding length in bytes. |

## sectionProperties

`provisional`

|       |                                                                                              |
|------:|----------------------------------------------------------------------------------------------|
|  Name | **sectionProperties**                                                                        |
|  Type | `std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>>`                                      |
| Value | Map from section UUIDs to a tuple with the section type constant and section flags constant. |

Integer constants are defined by the binary format specification:
- [ELF Section Types][ELFSHT]
- [ELF Section Flags][ELFSHF]
- [PE Section Characteristics][PECHAR]

_Note that the section type value is always 0 for PE sections._

[ELFSHT]: https://github.com/torvalds/linux/blob/dcf8e5633e2e69ad60b730ab5905608b756a032f/include/uapi/linux/elf.h#L271
[ELFSHF]: https://github.com/torvalds/linux/blob/dcf8e5633e2e69ad60b730ab5905608b756a032f/include/uapi/linux/elf.h#L290
[PECHAR]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics

## symbolForwarding

`sanctioned`

|       |                                                                                              |
|------:|---------------------------------------------------------------------------------------------|
|  Name | **symbolForwarding**                                                                        |
|  Type | `std::map<gtirb::UUID, gtirb::UUID>`                                                        |
| Value | Map one symbol to another symbol. (Used for flattening linker-induced indirect references.) |

This table is used to forward relocation symbols like those in ELF `PLT` and
`GOT` tables and PE incrementally linked jump thunks.

## symbolicExpressionSizes

`provisional`

|       |                                                                                               |
|------:|-----------------------------------------------------------------------------------------------|
|  Name | **symbolicExpressionSizes**                                                                   |
|  Type | `std::map<gtirb::Offset, uint64_t>`                                                           |
| Value | Map from an Offset of a symbolic expression in a ByteInterval to its extent, a size in bytes. |

## encodings

`provisional`

|       |                                                                                                                                                                       |
|------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  Name | **encodings**                                                                                                                                                         |
|  Type | `std::map<gtirb::UUID, std::string>`                                                                                                                                  |
| Value | Map from (typed) data objects to the encoding of the data, expressed as a `std::string` containing an assembler encoding specifier: "string", "uleb128" or "sleb128". |


## functionEntries

`sanctioned`

|       |                                                             |
|------:|-------------------------------------------------------------|
|  Name | **functionEntries**                                         |
|  Type | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`              |
| Value | UUIDs of the blocks that are entry points of each function. |
|       |                                                             |

## functionBlocks

`sanctioned`

|       |                                                   |
|------:|---------------------------------------------------|
|  Name | **functionBlocks**                                |
|  Type | `std::map<gtirb::UUID, std::set<gtirb::UUID>>`    |
| Value | UUIDs of the blocks that belong to each function. |

## functionNames

`sanctioned`

|       |                                                              |
|------:|--------------------------------------------------------------|
|  Name | **functionNames**                                            |
|  Type | `std::map<gtirb::UUID, gtirb::UUID>`                         |
| Value | UUID of the symbol holding the string name of each function. |

## SCCs

`provisional`

|       |                                                                                                                                          |
|------:|------------------------------------------------------------------------------------------------------------------------------------------|
|  Name | **SCCs**                                                                                                                                 |
|  Type | `std::map<gtirb::UUID, int64_t>`                                                                                                         |
| Value | Map UUID of blocks to an identifier for a intra-procedural subgraph it belongs to, i.e. a Strongly Connected Component (SCC) identifier. |

## libraries

`provisional`

|       |                                         |
|------:|-----------------------------------------|
|  Name | **libraries**                           |
|  Type | `std::vector<std::string>`              |
| Value | Names of the libraries that are needed. |

## libraryPaths

`provisional`

|       |                                             |
|------:|---------------------------------------------|
|  Name | **libraryPaths**                            |
|  Type | `std::vector<std::string>`                  |
| Value | Paths contained in the rpath of the binary. |

## souffleFacts

`unsanctioned`

|       |                                                                                    |
|------:|------------------------------------------------------------------------------------|
|  Name | **souffleFacts**                                                                   |
|  Type | `std::map<std::string, std::tuple<std::string, std::string>>`                      |
| Value | Map of Souffle facts by relation name to their associated type signatures and CSV. |

## souffleOutputs

`unsanctioned`

|       |                                                                                      |
|------:|--------------------------------------------------------------------------------------|
|  Name | **souffleOutputs**                                                                   |
|  Type | `std::map<std::string, std::tuple<std::string, std::string>>`                        |
| Value | Map of Souffle outputs by relation name to their associated type signatures and CSV. |
|       |                                                                                      |

## ELF

## dynamicEntries

`unsanctioned`

|       |                                               |
|------:|-----------------------------------------------|
|  Name | **dynamicEntries**                            |
|  Type | `std::set<std::tuple<std::string, uint64_t>>` |
| Value | Dynamic section entries: Name and value.      |

## sectionIndex

`unsanctioned`

|       |                                                |
|------:|------------------------------------------------|
|  Name | **sectionIndex**                               |
|  Type | `std::map<uint64_t, gtirb::UUID>`              |
| Value | Map from ELF section indices to section UUIDs. |

## elfSymbolInfo

`provisional`

|       |                                                                                                                                                                                                                                                                                                                                                                                                     |
|------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  Name | **elfSymbolInfo**                                                                                                                                                                                                                                                                                                                                                                                   |
|  Type | `std::map<gtirb::UUID, std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>>`                                                                                                                                                                                                                                                                                                      |
| Value | Map from symbol UUIDs to their ELF Symbol information containing the Size, Type, Binding, Visibility, and SectionIndex of the symbol.  Type can be "NOTYPE", "OBJECT", "FUNC", etc. Binding can be "LOCAL", "GLOBAL", or "WEAK". Visibility can be "DEFAULT", "HIDDEN", "PROTECTED", etc. For a complete list of possible values see e.g. https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html |

## elfSymbolTabIdxInfo

`unsanctioned`

|       |                                                                                                                                                                                                |
|------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  Name | **elfSymbolTabIdxInfo**                                                                                                                                                                        |
|  Type | `std::map<gtirb::UUID, std::vector<std::tuple<std::string, uint64_t>>>`                                                                                                                        |
| Value | Map from symbol UUIDs to symbol section information including the names of the symbol tables where the symbol was declared (typically ".dynsym" or ".symtab") and the index within that table. |

## elfSymbolVersions

`provisional`

|       |                                                                                                                  |
|------:|------------------------------------------------------------------------------------------------------------------|
|  Name | **elfSymbolVersions**                                                                                            |
|  Type | `std::tuple<ElfSymVerDefs,ElfSymVerNeeded,ElfSymbolVersionsEntries>`                                             |
| Value | Tuple with symbol version definitions, needed symbol versions, and a mapping of symbol UUIDs to symbol versions. |


1. `ElfSymverDefs = std::map<SymbolVersionId, std::tuple<std::vector<std::string>>, uint16_t>`

Symbol version definitions are a map from symbol version identifiers version
definitions. These correspond to `ELFxx_Verdef` entries in the ELF section
`.gnu.version_d`. The values in the map are tuples containing the list of
versions strings and the verdef flags. The verdef flag may be `VER_FLG_BASE`
(0x1), which indicates that the given version definition is the file itself,
and must not be used for matching a symbol. The first element of the list is
the version itself, the subsequent elements are predecessor versions.

2. `ElfSymVerNeeded = std::map<std::string, std::map<SymbolVersionId, std::string>>`

The needed symbol versions are a map from dynamic library names to the symbol
versions that they need. For each library, we have a map from version
identifiers to version strings.

3. `ElfSymbolVersionsEntries = std::map<gtirb::UUID, std::tuple<SymbolVersionId,bool>>`

Symbol UUIDs are mapped to symbol versions where the `bool` represents the
`HIDDEN` attribute. Symbol version identifiers are `SymbolVersionId = uint16_t`
integers.

|       |                                                                                                    |
|------:|----------------------------------------------------------------------------------------------------|
|  Name | **cfiDirectives**                                                                                  |
|  Type | `std::map<gtirb::Offset, std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>` |
| Value | Map from Offsets to vector of cfi directives.                                                      |

A cfi directive contains: a string describing the directive, a vector of numeric
arguments, and an optional symbolic argument (represented with the UUID of the
symbol).

## PE

### peImportEntries

`provisional`

|       |                                                                                                          |
|------:|----------------------------------------------------------------------------------------------------------|
|  Name | **peImportEntries**                                                                                      |
|  Type | `std::vector<std::tuple<uint64_t, int64_t, std::string, std::string>>`                                   |
| Value | List of tuples detailing an imported function address, ordinal, function name, and library names for PE. |


### peExportEntries

`provisional`

|       |                                                                         |
|------:|-------------------------------------------------------------------------|
|  Name | **peExportEntries**                                                     |
|  Type | `std::vector<std::tuple<uint64_t, int64_t, std::string>>`               |
| Value | List of tuples detailing an exported address, ordinal, and name for PE. |
|       |                                                                         |

## peImportedSymbols

`provisional`

|       |                                       |
|------:|---------------------------------------|
|  Name | **peImportedSymbols**                 |
|  Type | `std::vector<gtirb::UUID>`            |
| Value | UUIDs of the imported symbols for PE. |
|       |                                       |

## peExportedSymbols

`provisional`

|       |                                       |
|------:|---------------------------------------|
|  Name | **peExportedSymbols**                 |
|  Type | `std::vector<gtirb::UUID>`            |
| Value | UUIDs of the exported symbols for PE. |

## peSafeExceptionHandlers

`provisional`

|       |                                                                                                                                  |
|------:|----------------------------------------------------------------------------------------------------------------------------------|
|  Name | **peSafeExceptionHandlers**                                                                                                      |
|  Type | `std::set<gtirb::UUID>`                                                                                                          |
| Value | UUIDs of the blocks in the `SEHandlerTable` pointer array of safe exception handlers for PE32 binaries compiled with `/SAFESEH`. |

## peResource

`provisional`

|       |                                                                          |
|------:|--------------------------------------------------------------------------|
|  Name | **peResource**                                                           |
|  Type | `std::vector<std::tuple<std::vector<uint8_t>, gtirb::Offset, uint64_t>>` |
| Value | List of PE resources. A resource header, data length, and data pointer.  |

## peLoadConfig

`unsanctioned`

|       |                                                              |
|------:|--------------------------------------------------------------|
|  Name | **peLoadConfig**                                             |
|  Type | `std::map<std::string, uint64_t>`                            |
| Value | Map of PE load configuration field names to integral values. |

See the `_IMAGE_LOAD_CONFIG_DIRECTORY32` struct in `WINNT.h` for a complete list
of fields and [The Load Configuration Structure][LOADCONFIG] for additional information.

[LOADCONFIG]: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-load-configuration-structure-image-only
