import contextlib
from pathlib import Path
import os
import subprocess
import tempfile
import typing

import gtirb


class SnippetTestException(Exception):
    """
    Custom exceptions raised by snippet tests
    """


@contextlib.contextmanager
def assemble_snippet(
    snippet: str, arch=gtirb.Module.ISA
) -> typing.Generator[Path, None, None]:
    """
    Assemble an assembly snippet and return a path to the binary.

    The snippet becomes embedded in the function `main`, and the symbol
    `main_end` is placed at the end of the snippet.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        if arch == gtirb.Module.ISA.ARM:
            compiler = "arm-linux-gnueabihf-gcc"
            ret = "bx lr"
            type_prefix = "%"
        elif arch == gtirb.Module.ISA.X64:
            compiler = "gcc"
            ret = "retq"
            type_prefix = "@"
        else:
            raise SnippetTestException(f"Unimplemented snippet arch: {arch}")

        src_path = os.path.join(tmpdir, "test.s")
        with open(src_path, "w") as f:
            f.write(
                f"""
                .globl main
                .type main, {type_prefix}function
                main:
                {snippet}
                {ret}
                .globl main_end
                main_end:
                """
            )

        binary_path = os.path.join(tmpdir, "testtmp")

        cmd = [compiler, "-o", binary_path, src_path]
        subprocess.run(cmd, check=True)
        yield binary_path


def disassemble_to_gtirb(target: str) -> gtirb.Module:
    """
    Disassemble a binary and return the loaded GTIRB module
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        gtirb_path = os.path.join(tmpdir, "tmp.gtirb")
        cmd = [
            "ddisasm",
            target,
            "--ir",
            gtirb_path,
            "-j",
            "1",
            # Needed so stack_def_use.def_used is is available.
            "--with-souffle-relations",
        ]
        subprocess.run(cmd, timeout=60, check=True)

        loaded_gtirb = gtirb.IR.load_protobuf(gtirb_path)
        return loaded_gtirb.modules[0]


def asm_to_gtirb(
    snippet: str, arch: gtirb.Module.ISA = gtirb.Module.ISA.X64
) -> gtirb.Module:
    """
    Build and load a gtirb module for an assembly snippet
    """
    with assemble_snippet(snippet, arch=arch) as binary:
        return disassemble_to_gtirb(binary)


def snippet_bounds(module: gtirb.Module) -> typing.Tuple[int, int]:
    """
    Get a tuple representing a snippet's address range

    Works for snippets assembled with assemble_snippet
    """
    # snippets built with assemble_snippet bound the snippet with the symbols
    # `main` and `main_end`
    bounds = []
    for sym_name in ("main", "main_end"):
        for sym in module.symbols:
            if sym.name == sym_name:
                break
        else:
            raise SnippetTestException(f"No symbol: '{sym_name}'")

        if sym.referent is None:
            raise SnippetTestException(f"No referent: '{sym_name}'")

        if sym.referent.address is None:
            raise SnippetTestException(f"No address: '{sym_name}'")

        bounds.append(sym.referent.address)
    return tuple(bounds)


def parse_field(field: str, type_spec: str) -> typing.Any:
    """
    Parse a field in a tuple
    """
    base_type = type_spec.split(":")[1]

    if base_type in ("i", "u"):
        # base=0 supports both prefixed hexadecimal and decimal
        value = int(field, base=0)
    elif base_type == "s":
        value = field
    elif base_type == "r":
        value = parse_record(field, type_spec)
    else:
        raise SnippetTestException("Cannot parse type: " + str(type_spec))

    return value


def parse_record(record_str: str, type_spec: str) -> typing.Tuple[typing.Any]:
    """
    Parse a record entry using a type spec generator
    """
    record_types = {"stack_var": "BaseReg:s:register,StackPos:i:number"}
    type_name = type_spec.split(":")[2]
    type_spec = record_types[type_name]

    # strip brackets
    record_str = record_str.strip("[]")

    field_types = type_spec.split(",")
    parsed_fields = []

    # we can't just split the fields by ", " since there might be nested
    # records.
    for i, t in enumerate(field_types):
        if i == len(field_types) - 1:
            field = record_str
            record_str = ""
        else:
            field, record_str = record_str.split(", ", 1)

        parsed_fields.append(parse_field(field, t))
    return tuple(parsed_fields)


def parse_souffle_output(module: gtirb.Module, relation_name: str):
    """
    Parse a relation from the souffleOutputs auxdata
    """
    type_spec, data = module.aux_data["souffleOutputs"].data[
        "disassembly." + relation_name
    ]
    type_spec = type_spec.strip("<>")

    lines = data.strip().split("\n")
    if lines[0] == "":
        # empty relation
        return
    for line in lines:
        fields = line.split("\t")

        parsed_fields = []
        for field, t in zip(fields, type_spec.split(",")):
            parsed_fields.append(parse_field(field, t))

        yield tuple(parsed_fields)
