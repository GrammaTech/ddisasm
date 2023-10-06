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
                # pushq   %rbp
                # movq    %rsp, %rbp
                # pop     %rbp
                # ret
                bi1 = gtirb.ByteInterval(
                    contents=b"\x55\x48\x89\xEC\x5D\xC3", address=0x40000
                )
                bi1.section = s

                bi2 = gtirb.ByteInterval(
                    contents=b"\x55\x48\x89\xEC\x5D\xC3", address=0x80000
                )
                bi2.section = s

                ir.save_protobuf("ex_raw")

                self.assertTrue(disassemble("ex_raw", format="--ir")[0])

                ir_disassembled = gtirb.IR.load_protobuf("ex_raw.gtirb")
                m = ir_disassembled.modules[0]
                code_addresses = sorted(
                    [block.address for block in m.code_blocks]
                )
                self.assertEqual(code_addresses, [0x40000, 0x80000])

    def test_gtirb_with_clues(self):
        """
        Test that we can correctly handle a GTIRB
        with holes within a section.
        """

        with tempfile.TemporaryDirectory() as dir:
            with cd(dir):
                ir, s = create_basic_gtirb()
                # 0e (invalid)
                # pushq   %rbp
                # movq    %rsp, %rbp
                # pop     %rbp
                # ret
                # pushq   %rbp
                # movq    %rsp, %rbp
                # pop     %rbp
                # ret
                bi1 = gtirb.ByteInterval(
                    contents=b"\x0e\x55\x48\x89\xEC\x5D"
                    b"\xC3\x55\x48\x89\xEC\x5D\xC3",
                    address=0x40000,
                )
                bi1.section = s
                gtirb.CodeBlock(size=6, offset=1, byte_interval=bi1)

                # 0e (invalid)
                # pushq   %rbp
                # movq    %rsp, %rbp
                # pop     %rbp
                # ret
                bi2 = gtirb.ByteInterval(
                    contents=b"\x0e\x55\x48\x89\xEC\x5D\xC3", address=0x80000
                )
                bi2.section = s

                gtirb.CodeBlock(size=6, offset=1, byte_interval=bi2)
                ir.save_protobuf("ex_raw")

                self.assertTrue(disassemble("ex_raw", format="--ir")[0])

                ir_disassembled = gtirb.IR.load_protobuf("ex_raw.gtirb")
                m = ir_disassembled.modules[0]
                # the resulting gtirb has 3 blocks
                # the two previous one and one additionally discovered
                code_addresses = sorted(
                    [block.address for block in m.code_blocks]
                )
                self.assertEqual(code_addresses, [0x40001, 0x40007, 0x80001])
