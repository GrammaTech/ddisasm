import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"


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
            self.assertTrue(disassemble(binary, format="--ir")[0])

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
    def test_switch_overlap(self):
        """
        Test that with two overlapping jumptables, a conherent jump table is
        generated.
        """
        binary = "ex"
        with cd(ex_asm_dir / "ex_switch_overlap"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

        rodata = next(s for s in m.sections if s.name == ".jumptable")
        ref = None
        count = 0
        for _, _, symexpr in rodata.symbolic_expressions_at(
            range(rodata.address, rodata.address + rodata.size)
        ):
            if not isinstance(symexpr, gtirb.symbolicexpression.SymAddrAddr):
                continue

            # confirm all symexpr have the same ref
            if count == 0:
                ref = symexpr.symbol2

            self.assertEqual(symexpr.symbol2.name, ref.name)
            count += 1
        self.assertEqual(count, 4)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_64_object_cfg(self):
        """
        Test X86_64 object file relocation edges.
        """
        binary = "ex.o"
        with cd(ex_dir / "ex1"):
            self.assertTrue(compile("gcc", "g++", "-O0", ["--save-temps"]))
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            call = b"\xe8\x00\x00\x00\x00"
            blocks = [b for b in m.code_blocks if b.contents.endswith(call)]
            self.assertTrue(
                all(len(list(b.outgoing_edges)) == 2 for b in blocks)
            )


if __name__ == "__main__":
    unittest.main()
