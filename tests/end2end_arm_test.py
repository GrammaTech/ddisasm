import platform
import unittest
from disassemble_reassemble_check import (
    disassemble_reassemble_test as dis_reasm_test,
)
from pathlib import Path

asm_dir = Path("./examples/arm_asm_examples/")


class TestArmAsmExamples(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_asm_ex1(self):
        self.assertTrue(
            dis_reasm_test(
                asm_dir / "ex1_pie",
                "ex",
                c_compilers=["arm-linux-gnueabihf-gcc"],
                cxx_compilers=["arm-linux-gnueabihf-g++"],
                reassembly_compiler="arm-linux-gnueabihf-gcc",
                extra_reassemble_flags=["-pie"],
                optimizations=[""],
            )
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_asm_ex1_no_pie(self):
        self.assertTrue(
            dis_reasm_test(
                asm_dir / "ex1_no_pie",
                "ex",
                c_compilers=["arm-linux-gnueabihf-gcc"],
                cxx_compilers=["arm-linux-gnueabihf-g++"],
                reassembly_compiler="arm-linux-gnueabihf-gcc",
                extra_reassemble_flags=["-no-pie"],
                optimizations=[""],
            )
        )


if __name__ == "__main__":
    unittest.main()
