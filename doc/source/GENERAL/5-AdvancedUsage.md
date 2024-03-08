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

You can consult the Datalog API reference https://grammatech.github.io/ddisasm/APIRef.html
for details on the internal Ddisasm predicates.

### Changing heuristic weights with hints

The code inference algorithm uses several heuristics to determine what is code and what is data.
Each heuristic has a weight associated to it, i.e. how many points a block candidate gets for a given
heuristic.

Users can modify the heuristic weights by providing hints with the `user_heuristic_weight` predicate.
For example, the following hint:
```
disassembly.user_heuristic_weight   overlaps with relocation simple -4
```
changes the weight of the "overlaps with relocation" heuristic to -4.
