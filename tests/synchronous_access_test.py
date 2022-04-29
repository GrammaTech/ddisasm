import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_asm_dir = Path("./examples/") / "asm_examples"


class SynchronousAccessTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_synchronous_access_in_bss(self):
        """
        Test that the bss section does not get split by
        a synchronous access.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_synchronous_access"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir", strip=True)[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            bss_section = next(s for s in m.sections if s.name == ".bss")
            # There is a code block in .bss of size 80
            self.assertIn(
                80, [block.size for block in bss_section.data_blocks]
            )

    def test_propagate_through_synchronous_accesses(self):
        """
        Test that the data accesses propagate through
        synchronous accesses all the way.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_synchronous_access2"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(
                disassemble(
                    binary,
                    format="--ir",
                    strip=True,
                    extra_args=["--with-souffle-relations"],
                )[0]
            )

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            data_section = next(s for s in m.sections if s.name == ".data")

            preferred_data_access = m.aux_data["souffleOutputs"].data[
                "preferred_data_access"
            ]
            addresses = [
                int(x.split("\t")[0])
                for x in preferred_data_access[1].strip().split("\n")
            ]

            addresses_in_data = [
                addr
                for addr in addresses
                if addr >= data_section.address
                and addr < data_section.address + data_section.size
            ]
            # Three syncrhonized accesses propagated in a loop with 10 elements
            self.assertGreaterEqual(len(addresses_in_data), 30)


if __name__ == "__main__":
    unittest.main()
