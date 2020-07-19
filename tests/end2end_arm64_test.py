import distro
import unittest
from disassemble_reassemble_check import (
    disassemble_reassemble_test as dis_reasm_test,
)
from pathlib import Path

asm_dir = Path("./examples/arm64/")


class TestArm64BinratsExamples(unittest.TestCase):
    @unittest.skipUnless(
        distro.id() == "ubuntu" and distro.major_version() in ("18", "20"),
        "This test is Ubuntu 18 and 20 only.",
    )
    def test_arm64_binrats_hello(self):
        self.assertTrue(
            dis_reasm_test(
                asm_dir / "hello",
                "hello",
                c_compilers=["aarch64-linux-gnu-gcc"],
                cxx_compilers=["aarch64-linux-gnu-g++"],
                reassembly_compiler="aarch64-linux-gnu-gcc",
            )
        )

    # FIXME: Propagate invalid operands to invalid instructions.
    # @unittest.skipUnless(distro.id() == "ubuntu",
    # "This test is Ubuntu only.")
    # def test_arm64_binrats_password(self):
    #     self.assertTrue(
    #         dis_reasm_test(
    #             asm_dir / "password",
    #             "password",
    #             c_compilers=["aarch64-linux-gnu-gcc"],
    #             cxx_compilers=["aarch64-linux-gnu-g++"],
    #             reassembly_compiler="aarch64-linux-gnu-gcc",
    #         )
    #     )


if __name__ == "__main__":
    unittest.main()
