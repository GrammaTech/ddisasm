# RFC: MSVC Profile Guided Optimization Support

## Objective

Add support for PE32 binaries compiled with Microsoft's Profile Guided
Optimization (POGO).

Improving code-data discrimination in ddisasm code-inference analysis.

https://devblogs.microsoft.com/cppblog/pogo/
https://docs.microsoft.com/en-us/cpp/build/profile-guided-optimizations?view=msvc-160

## Overview

Profile Guided Optimization (PGO or POGO) has not reportedly seen wide-spread
adoption, but the three projects that supposedly do release optimized binaries
are all desirable targets for ddisasm: JVM, Firefox, and Chrome.

These targets are long-term goals, but the central problem faced in POGO
binaries is a more fundamental one - differentiating between data and code.

Consider the POGO debug entries from the Firefox 32-bit DLL `d3dcompiler_47.dll`:

```
             RVA     Size  Name
        -------- --------  ----
        00001000    273D8  .rdata$brc
        000283D8        4  .CRT$XCA
        000283DC        4  .CRT$XCL
        000283E0       48  .CRT$XCU
        00028428        4  .CRT$XCZ
        0002842C        4  .CRT$XIA
        00028430        4  .CRT$XIAA
        00028434        4  .CRT$XIZ
        00028438     3C28  .gfids
        0002C060       10  .giats
        0002C070    6DC30  .rdata
        00099CA0       88  .rdata$sxdata
        00099D28      2F8  .rdata$zzzdbg
        0009A020       80  .text$cthunks
        0009A0A0     5280  .text$di
        0009F320   2AFE60  .text$mn
        0034F180       10  .text$mn$00
        0034F190      910  .text$src
        0034FAA0     1530  .text$tii
        00350FD0     1D90  .text$wti
        00352D60      7A0  .text$x
        00353500      468  .text$yd
        00353968      DD8  .xdata$x
        00354740      375  .edata
        ...
```

All of these entries are inside of the `.text` section. Notice that very many of
them have names indicating they are actually data and not code.

Our current code inference analysis is very limited in the resolution of data in
code. We only actively attempt to find jump tables (`relative_address`), and
incidentally find data regions between or after well-defined code blocks
(`data_in_code`).

## Possible Solutions

Supporting POGO reduces to either an ad-hoc solution that leverages the above
table or improving code-data inference in general.

1. Ad-hoc POGO entry rules.
  Use the `name` field of the POGO debug entries to differeniate between code
  and data regions (i.e. anything without a `.text` prefix is data).

  We would need to add relations to `code_inference.dl` that would allow us
  to exclude known data regions from block candidacy.

2. Generalized code-data heuristics
  A number of repeating patterns present in these data regions. Patterns that
  make it obvious to a human that they are definitely data and not code. These
  should be readily translatable to Datalog logic.

  - Long sequences of repeated addresses
  - Repeated addresses with some uniform byte/dword/qword separator
  - Long null regions
  - Regular/consistent data access patterns
  - Code blocks that interrupt data but are not well-defined targets
  - Incoherent per-block use-def (disjunct register usage in a basic block)

Note that regardless of how we choose to proceed it is most important we build a
definitive solution for region-exclusion in `code_inference.dl`. We currently
do code block candidate selection first and then data object candidate selection.

I propose we rework the `data_in_code` relation to preform a pre-code-inference
pass that excludes either by `.input` or by implementing the above heuristics to
find and exclude regions from code block candidacy.
