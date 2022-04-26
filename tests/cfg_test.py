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
            self.assertTrue(disassemble(binary, format="--ir")[0])

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
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            sym = [s for s in m.symbols if s.name == "main"][0]
            block = sym.referent
            self.assertEqual(len(list(block.outgoing_edges)), 2)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_cfg_bx_pc(self):
        """
        Test ARM32 CFG
        """
        binary = "ex"
        adder_dir = ex_arm_asm_dir / "ex_bx_pc"
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
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            sym = [s for s in m.symbols if s.name == "main"][0]
            block = sym.referent
            self.assertEqual(len(list(block.outgoing_edges)), 1)

            edge = list(block.outgoing_edges)[0]
            self.assertEqual(edge.label.type, gtirb.Edge.Type.Branch)
            self.assertIsInstance(edge.target, gtirb.CodeBlock)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_cfg2(self):
        """
        Test ARM32 CFG
        """
        binary = "ex"
        adder_dir = ex_arm_asm_dir / "ex_cfg"
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
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            main = [s for s in m.symbols if s.name == "main"][0]
            main_block = main.referent

            # check on bxeq lr

            self.assertEqual(len(list(main_block.outgoing_edges)), 2)

            edge_types = {e.label.type for e in main_block.outgoing_edges}
            self.assertEqual(
                edge_types,
                {gtirb.Edge.Type.Fallthrough, gtirb.Edge.Type.Return},
            )

            edge1 = list(main_block.outgoing_edges)[0]
            edge2 = list(main_block.outgoing_edges)[1]
            if edge1.label.type == gtirb.Edge.Type.Return:
                self.assertTrue(edge1.label.conditional)
            if edge2.label.type == gtirb.Edge.Type.Return:
                self.assertTrue(edge2.label.conditional)

            # check on bx lr
            sym = [s for s in m.symbols if s.name == "foo"][0]
            bx_block = sym.referent

            self.assertEqual(len(list(bx_block.outgoing_edges)), 1)

            edge = list(bx_block.outgoing_edges)[0]
            self.assertEqual(edge.label.type, gtirb.Edge.Type.Return)

            # check on blx foo
            insn_blx = b"\x00\xf0"

            for block in m.code_blocks:
                if (
                    block.address >= main_block.address
                    and block.contents[:2] == insn_blx
                ):
                    blx_block = block

            self.assertEqual(len(list(blx_block.outgoing_edges)), 2)

            edge_types = {e.label.type for e in blx_block.outgoing_edges}
            self.assertEqual(
                edge_types, {gtirb.Edge.Type.Fallthrough, gtirb.Edge.Type.Call}
            )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_tbb_cfg(self):
        """
        Test ARM32 CFG from a TBB jumptable
        """
        binary = "ex"
        with cd(ex_arm_asm_dir / "ex_tbb"):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )
            self.assertTrue(disassemble(binary, format="--ir")[0])

            # test_relative_jump_tables relies on symbols to find the expected
            # source and target blocks. However, ARM doesn't seem to match the
            # symbols with CodeBlocks correctly, so we work around it.

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            # Locate the tbb instruction
            jumping_block = None
            expected_dest_blocks = []

            for block in m.code_blocks:
                # search for tbb [pc, r3]
                if block.contents[:4] == b"\xdf\xe8\x00\xf0":
                    jumping_block = block

                # search for nop
                elif block.contents[:2] == b"\x00\xbf":
                    expected_dest_blocks.append(block)

            # check that the tbb block has edges to all the jump table entries
            self.assertEqual(len(list(jumping_block.outgoing_edges)), 4)
            dest_blocks = [e.target for e in jumping_block.outgoing_edges]
            self.assertEqual(set(dest_blocks), set(expected_dest_blocks))

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

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_jumptable_cfg(self):
        """
        Test ARM32 CFG on a ldrls pc, [pc, r0, LSL2]-style jumptable.
        """
        binary = "ex"
        adder_dir = ex_arm_asm_dir / "ex_jumptable"
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
                    strip_exe="arm-linux-gnueabihf-strip",
                    strip=True,
                    format="--ir",
                )
            )

            # ldrls pc, [pc, r0, LSL2]
            insn = b"\x00\xf1\x9f\x97"

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            jumping_block = None
            for block in m.code_blocks:
                if block.contents.endswith(insn):
                    jumping_block = block

            self.assertIsNotNone(jumping_block)

            edges_by_type = {
                gtirb.Edge.Type.Branch: [],
                gtirb.Edge.Type.Fallthrough: [],
            }

            for edge in jumping_block.outgoing_edges:
                if edge.label.type not in edges_by_type:
                    self.fail(
                        "Unexpected edge type: {}".format(edge.label.type)
                    )
                edges_by_type[edge.label.type].append(edge)

            self.assertEqual(6, len(edges_by_type[gtirb.Edge.Type.Branch]))
            self.assertEqual(
                1, len(edges_by_type[gtirb.Edge.Type.Fallthrough])
            )

            for edges in edges_by_type[gtirb.Edge.Type.Branch]:
                self.assertIsInstance(edge.target, gtirb.CodeBlock)


if __name__ == "__main__":
    unittest.main()
