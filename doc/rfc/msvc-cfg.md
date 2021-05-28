# RFC: MSVC Control Flow Guard Support

## Objective

Add support for PE32 binaries compiled with Microsoft's Control Flow Guard.

https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
https://docs.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard?view=msvc-160
https://lucasg.github.io/2017/02/05/Control-Flow-Guard/

## Overview

PE32 binaries can be compiled with natively support control flow integrity
protections by passing the `CL` compiler the `/guard:cf` option.

When enabled the MSVC compiler and linker insert instrumentation and
configuration that enable runtime security checks on indirect calls.

Indirect calls are replaced with a placeholder `_guard_check_icall` function,
which is replaced when the binary is loaded with a function that checks branch
destinations against a whitelist.

The whitelist of safe destinations is also kept on the binary. The PE header has
a data directory designated as the "load configuration". The load config data
directory points to a structure in the binary with control flow guard fields.

Lastly, the use of Control Flow Guard is indicated by a characteristic flag on
the optional header of the PE (IMAGE_DLL_CHARACTERISTICS_GUARD_CF).

https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

We do currently not support the preservation of data directories or flag parity.

## Possible Solutions

1. Strip Control Flow Guard

The most direct solution is to provide an auxiliary transform script that can
strip the whitelist table, data directory structure, and replace the
`_guard_check_icall` placeholder.

TODO: Write minimal example that uses Control Flow Guard to protect an indirect
branch for testing. Test toggling the flag off:

```python
import lief
pe = lief.parse("/path/to/example.exe")
pe = pe.optional_header.dll_characteristics ^= lief.PE.DLL_CHARACTERISTICS.GUARD_CF
pe.write("/path/to/modified.exe")
```

2. Re-minted Control Flow Guard

Another solution that would preserve the support of would be to re-symbolize the
load config struct, and provide a post-processing script to restore the PE
header flags and data directory entries.

This brings up the more general question of support for saving/restoring data
directories and restoring flags on a reassembled PE.

I don't think that MASM will have any builtin support for affecting these. We
have already made one concession to PE here with the `--generate-import-libs`
flag.

Perhaps we want to build a separate utility that is capable of performing all of
these tasks.
