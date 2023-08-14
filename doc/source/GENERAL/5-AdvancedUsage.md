# Advanced Usage


## Providing User Hints

A user can provide a file with user hints to guide and overcome limitations in the current ddisasm
implementation. User hints are simply datalog facts that are added to the database before running
the Datalog program. Datalog hints are provided in tab-separated .csv format where the first field
is the predicate name namespaced with the pass name and subsequent fields are the fact field values
to be added.

For example
```
disassembly.invalid 0x100 definitely_not_code
```
will add a fact `invalid(0x100,"definitely_not_code")` to the Datalog database of the disassembly pass.
The fields need to be separated by tabs '\t'.
