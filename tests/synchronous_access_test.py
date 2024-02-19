import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path


ex_dir = Path("./examples/")
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
        for exdir in (ex_dir, ex_asm_dir):
            with self.subTest(example=exdir / "ex_synchronous_access"):
                binary = Path("ex")
                with cd(exdir / "ex_synchronous_access"):
                    self.assertTrue(compile("gcc", "g++", "-O0", []))
                    ir_library = disassemble(binary, strip=True).ir()
                    m = ir_library.modules[0]

                    bss_section = next(
                        s for s in m.sections if s.name == ".bss"
                    )
                    # There is a data block in .bss of size 80
                    self.assertIn(
                        80, [block.size for block in bss_section.data_blocks]
                    )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_propagate_through_synchronous_accesses(self):
        """
        Test that the data accesses propagate through
        synchronous accesses all the way.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_synchronous_access2"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(
                binary,
                strip=True,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]

            data_section = next(s for s in m.sections if s.name == ".data")

            preferred_data_access = m.aux_data["souffleOutputs"].data[
                "disassembly.preferred_data_access"
            ]
            addresses = [
                int(x.split("\t")[0], base=16)
                for x in preferred_data_access[1].strip().split("\n")
            ]

            addresses_in_data = [
                addr
                for addr in addresses
                if addr >= data_section.address
                and addr < data_section.address + data_section.size
            ]
            # Three synchronized accesses propagated in a loop with 10 elements
            self.assertGreaterEqual(len(addresses_in_data), 30)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_synchronous_access_barrier(self):
        """
        Test that any incorrect synchronous access is created
        given a barrier between candidate synchronous accesses.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_synchronous_access4"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(
                binary,
                strip=True,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]

            synchronous_access = m.aux_data["souffleOutputs"].data[
                "disassembly.synchronous_access"
            ]

            # There should not be any synchronous_access.
            self.assertTrue(not synchronous_access[1])


if __name__ == "__main__":
    unittest.main()
