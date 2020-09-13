import unittest
from pathlib import Path

import platform

from disassemble_reassemble_check import (
    cd,
    compile,
    disassemble_reassemble_test,
)

ex_dir = Path("./examples/")
asm_dir = Path("./examples/asm_examples/")


class TestSpecialFlags(unittest.TestCase):
    # test binary compiled with -fcf-protection
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_fcf_protection(self):
        # check if the -fcf-protection is supported by the compiler
        # (only newer versions support it)
        with cd(ex_dir / "ex1"):
            flag_supported = compile("gcc", "g++", "", ["-fcf-protection"])
        if flag_supported:
            self.assertTrue(
                dis_reasm_test(
                    ex_dir / "ex1",
                    "ex",
                    c_compilers=["gcc"],
                    cxx_compilers=["g++"],
                    optimizations=[""],
                    extra_compile_flags=["-fcf-protection"],
                )
            )
        else:
            print("Flag -fcf-protection not supported")


if __name__ == "__main__":
    unittest.main()
