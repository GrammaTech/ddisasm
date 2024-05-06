import platform
import unittest
from disassemble_reassemble_check import (
    cd,
    disassemble,
)
from pathlib import Path
import gtirb
import tempfile
from typing import Tuple

ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"


def create_basic_gtirb() -> Tuple[gtirb.IR, gtirb.Section]:
    """
    Create a gtirb with one executable section
    """
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.RAW,
        name="test",
        byte_order=gtirb.Module.ByteOrder.Little,
    )
    m.ir = ir
    flags = {
        gtirb.Section.Flag.Readable,
        gtirb.Section.Flag.Executable,
        gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Initialized,
    }
    s = gtirb.Section(name="blob", flags=flags)
    s.module = m
    return ir, s


class RawBinaryTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_section_with_two_byte_intervals(self):
        """
        Test that we can correctly handle a GTIRB
        with holes within a section.
        """

        with tempfile.TemporaryDirectory() as dir:
            with cd(dir):
                ir, s = create_basic_gtirb()
                bi1 = gtirb.ByteInterval(
                    contents=b"\x55"  # pushq   %rbp
                    b"\x48\x89\xEC"  # movq    %rsp, %rbp
                    b"\x5D"  # pop     %rbp
                    b"\xC3",  # ret
                    address=0x40000,
                )
                bi1.section = s

                bi2 = gtirb.ByteInterval(
                    contents=b"\x55"  # pushq   %rbp
                    b"\x48\x89\xEC"  # movq    %rsp, %rbp
                    b"\x5D"  # pop     %rbp
                    b"\xC3",  # ret
                    address=0x80000,
                )
                bi2.section = s

                ir_path_in = Path("ex_raw")
                ir.save_protobuf(ir_path_in)

                ir_disassembled = disassemble(ir_path_in).ir()
                m = ir_disassembled.modules[0]
                code_addresses = sorted(
                    [block.address for block in m.code_blocks]
                )
                self.assertEqual(code_addresses, [0x40000, 0x80000])

    def test_gtirb_with_clues(self):
        """
        Test that we can correctly handle a GTIRB
        with holes within a section.

        For raw binaries ddisasm allows calls or jumps
        to undefined destinations.
        """

        with tempfile.TemporaryDirectory() as dir:
            with cd(dir):
                ir, s = create_basic_gtirb()

                bi1 = gtirb.ByteInterval(
                    contents=b"\x0e"  # Invalid
                    b"\x55"  # pushq   %rbp
                    b"\x48\x89\xEC"  # movq    %rsp, %rbp
                    b"\x5D"  # pop     %rbp
                    b"\xC3"  # ret
                    b"\x55"  # pushq   %rbp
                    b"\x48\x89\xEC"  # movq    %rsp, %rbp
                    b"\x5D"  # pop     %rbp
                    b"\xE8\x03\x00\x00\x00"  # call RIP+3
                    b"\xC3",  # ret
                    address=0x40000,
                )
                bi1.section = s
                gtirb.CodeBlock(size=6, offset=1, byte_interval=bi1)

                bi2 = gtirb.ByteInterval(
                    contents=b"\x0e"  # Invalid
                    b"\x55"  # pushq   %rbp
                    b"\x48\x89\xEC"  # movq    %rsp, %rbp
                    b"\x5D"  # pop     %rbp
                    b"\xC3",  # ret
                    address=0x80000,
                )
                bi2.section = s

                gtirb.CodeBlock(size=6, offset=1, byte_interval=bi2)
                ir_path_in = Path("ex_raw")
                ir.save_protobuf(ir_path_in)

                ir_disassembled = disassemble(ir_path_in).ir()
                m = ir_disassembled.modules[0]
                # the resulting gtirb has 4 blocks
                # the two previous ones and two additionally discovered
                code_addresses = sorted(
                    [block.address for block in m.code_blocks]
                )
                self.assertEqual(
                    code_addresses, [0x40001, 0x40007, 0x40011, 0x80001]
                )
                data_addresses = sorted(
                    [block.address for block in m.data_blocks]
                )
                self.assertEqual(data_addresses, [0x40000, 0x80000])
                self.assertEqual({block.size for block in m.data_blocks}, {1})

    def test_code_section_without_code(self):
        """
        Test that a gtirb executable section without code
        generates a data object covering all the section
        """

        with tempfile.TemporaryDirectory() as dir:
            with cd(dir):
                ir, s = create_basic_gtirb()

                bi1 = gtirb.ByteInterval(
                    contents=b"\x0e\x0e\x0e\x0e\x0e",  # Invalid
                    address=0x40000,
                )
                bi1.section = s
                ir_path_in = Path("ex_raw")
                ir.save_protobuf(ir_path_in)
                ir_disassembled = disassemble(ir_path_in).ir()
                m = ir_disassembled.modules[0]
                # the code section has one data block
                dblocks = list(m.data_blocks)
                self.assertEqual(len(dblocks), 1)
                self.assertEqual(dblocks[0].address, 0x40000)
                self.assertEqual(dblocks[0].size, 5)
