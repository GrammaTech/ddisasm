import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"
ex_arm_asm_dir = ex_dir / "arm_asm_examples"


class CfgTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_relative_jump_tables(self):
        """
        Test edges for relative jump tables are added.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_relative_switch"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(
                disassemble(
                    binary,
                    "strip",
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                )
            )

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            # check that the jumping_block has edges
            # to all the jump table entries
            jumping_block_symbol = [
                s for s in m.symbols if s.name == "jumping_block"
            ][0]
            assert isinstance(jumping_block_symbol.referent, gtirb.CodeBlock)
            jumping_block = jumping_block_symbol.referent
            expected_dest_blocks = [
                s.referent
                for s in m.symbols
                if s.name in ["LBB5_4", "LBB5_5", "LBB5_6", "LBB5_7"]
            ]
            self.assertEqual(len(list(jumping_block.outgoing_edges)), 4)
            dest_blocks = [e.target for e in jumping_block.outgoing_edges]
            self.assertEqual(set(dest_blocks), set(expected_dest_blocks))

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_mips_cfg(self):
        """
        Test MIPS CFG
        """

        binary = "ex"
        adder_dir = ex_dir / "ex_adder"
        with cd(adder_dir):
            self.assertTrue(
                compile(
                    "mips-linux-gnu-gcc",
                    "mips-linux-gnu-g++",
                    "-O0",
                    [],
                    "qemu-mips -L /usr/mips-linux-gnu",
                )
            )
            self.assertTrue(
                disassemble(
                    binary,
                    "mips-linux-gnu-strip",
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                )
            )

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            # check that the 'add' block has two incoming edges and
            # two outgoing edges.
            add_symbol = [s for s in m.symbols if s.name == "add"][0]
            assert isinstance(add_symbol.referent, gtirb.CodeBlock)
            add_block = add_symbol.referent
            self.assertEqual(len(list(add_block.outgoing_edges)), 2)
            self.assertEqual(len(list(add_block.incoming_edges)), 2)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_cfg(self):
        """
        Test ARM32 CFG
        """

        binary = "ex"
        adder_dir = ex_arm_asm_dir / "ex1_no_pie"
        with cd(adder_dir):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )
            self.assertTrue(
                disassemble(
                    binary,
                    "arm-linux-gnueabihf-strip",
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                )
            )

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            sym = [
                s for s in m.symbols if s.name == "main"
            ][0]
            block = sym.referent
            self.assertEqual(len(list(block.outgoing_edges)), 2)


if __name__ == "__main__":
    unittest.main()
