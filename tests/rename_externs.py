#!/usr/bin/env python3

"""
Rename PE32 symbols.

> The compiler also decorates C functions that use the __stdcall calling
> convention with an underscore (_) prefix and a suffix composed of the at sign
> (@) followed by the number of bytes (in decimal) in the argument list.
>
> To find the decorated names produced by the compiler, use the DUMPBIN tool or
> the linker /MAP option.

https://docs.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-160

We parse `dumpbin /EXPORTS' output to find the mapping and replace all
instances of that symbol with the correct value.

For example,

EXTERN ExitProcess:PROC        -->    EXTERN ExitProcess@4:PROC

Similarly, the implicit underscore requires a transform of our redundant
`__imp' definitions as well.

EXTERN __imp_ExitProcess:PROC  -->    EXTERN _imp__ExitProcess:PROC


"""

import re
import sys
import subprocess

def rename_externs(asm, libs):
    # Call out to DUMPBIN for fully-qualified symbol names in .LIB files.
    mapping = {}
    for lib in libs:
        path = subprocess.check_output(["winepath", "--windows", lib.name]).strip()
        output = subprocess.check_output(["dumpbin", "/EXPORTS", path], encoding="utf-8")
        for match in re.finditer(r"\s+(_(\w+)@(\d+))\s*$", output, re.MULTILINE):
            _, name, argsize = match.groups()
            mapping[name] = argsize

    # Find externs in assembly.
    content = asm.read()
    externs = re.findall(r"^EXTERN (\w+):PROC$", content, re.MULTILINE)

    # Replace symbols.
    replacements = [
        ["EXTERN {}:PROC",            "EXTERN {}@{}:PROC"],
        ["jmp DWORD PTR {}$",          "jmp DWORD PTR {}@{}"],
        ["call DWORD PTR {}$",         "call DWORD PTR {}@{}"],

        ["EXTERN __imp_{}:PROC",      "EXTERN _imp__{}@{}:PROC"],
        ["call DWORD PTR __imp_{}$",   "call DWORD PTR _imp__{}@{}"],
        ["jmp DWORD PTR __imp_{}$",    "jmp DWORD PTR _imp__{}@{}"],
    ]
    for name in externs:
        if name in mapping:
            argsize = mapping[name]
            for a, b in replacements:
                content = re.sub(
                    a.format(name),
                    b.format(name, argsize),
                    content,
                    flags=re.MULTILINE
                )

    # Write contents back to file.
    asm.seek(0)
    asm.write(content)
    asm.truncate()
    asm.close()

def main(args):
    rename_externs(args.asm, args.libs)
    return 0

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("asm", metavar="ASM", type=argparse.FileType("r+"))
    parser.add_argument("libs", metavar="LIB", nargs="+", type=argparse.FileType("r"))
    args = parser.parse_args()
    sys.exit(main(args))
