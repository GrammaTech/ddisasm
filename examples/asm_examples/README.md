C examples tests have a big problem, they depend on the version of the compiler used. With different compiler version the examples can end up looking very different.

Asm examples can be use to exercise specific patterns without relying on the compiler installed in each machine to generate them.

This can be useful to exercise:
  - different kinds of pointer reatribution patterns
  - jump table patterns
  - weird constructs e.g. overlapping instructions, data in code sections, etc.
