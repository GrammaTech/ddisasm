import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_asm_dir = Path("./examples/") / "asm_examples"


class SynchronizedAccessTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_syncrhonized_access_in_bss(self):
        """
        Test a library that calls local methods through
        the plt table and locally defined symbols
        do not point to proxy blocks.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_synchronized_access"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir", strip=True)[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            bss_section = next(s for s in m.sections if s.name == ".bss")
            # There is a code block in .bss of size 80
            self.assertIn(
                80, [block.size for block in bss_section.data_blocks]
            )


if __name__ == "__main__":
    unittest.main()
