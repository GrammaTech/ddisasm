import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble, make
from pathlib import Path
import gtirb
import subprocess
import os
from gtirb.cfg import EdgeType, EdgeLabel
from typing import List, Dict, Tuple


ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"
ex_arm_asm_dir = ex_dir / "arm_asm_examples"
ex_arm64_asm_dir = ex_dir / "arm64_asm_examples"
ex_mips_asm_dir = ex_dir / "mips_asm_examples"


class CfgTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_relative_jump_tables(self):
        """
        Test edges for relative jump tables are added.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_relative_switch"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that the jumping_block has edges
            # to all the jump table entries
            jumping_block_symbol = next(m.symbols_named("jumping_block"))
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
    def test_relative_jump_table_with_cmov(self):
        """
        Make sure that the jump-table is not resolved when jump-table
        bounary cannot be conservatively found due to multiple correlations
        between the index register and the correlated register.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_relative_jump_tables4"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that the jump_table entry targets do not have
            # any incoming edge.
            jt_target5_sym = next(m.symbols_named(".jump_table_target5"))
            assert isinstance(jt_target5_sym.referent, gtirb.CodeBlock)
            jt_target5_block = jt_target5_sym.referent
            self.assertEqual(len(list(jt_target5_block.incoming_edges)), 0)

            jt_target6_sym = next(m.symbols_named(".jump_table_target6"))
            assert isinstance(jt_target6_sym.referent, gtirb.CodeBlock)
            jt_target6_block = jt_target6_sym.referent
            self.assertEqual(len(list(jt_target6_block.incoming_edges)), 0)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_switch_limited_by_cmp(self):
        """
        Ensure jump table propagation is limited by comparsions.
        """
        binary = Path("ex")
        examples = [
            "ex_switch_limited_by_cmp",
            "ex_switch_limited_by_indirect_cmp",
            "ex_switch_limited_index_table",
        ]

        for example in examples:
            with self.subTest(example=example):
                with cd(ex_asm_dir / example):
                    self.assertTrue(compile("gcc", "g++", "-O0", []))
                    ir_library = disassemble(binary).ir()
                    m = ir_library.modules[0]

                # check that the .jump has edges to only the four jump table
                # entries
                jump_sym = next(m.symbols_named(".jump"))
                self.assertEqual(
                    len(list(jump_sym.referent.outgoing_edges)), 4
                )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_switch_limited_by_cmp_arm64(self):
        """
        Ensure jump table propagation is limited by comparsions of the index
        register.
        """
        binary = Path("ex")
        with cd(ex_arm64_asm_dir / "ex_switch_limited_by_cmp"):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-g++", "-O0", []
                )
            )
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

        # check that the .jump has edges to only the four jump table entries
        jump_sym = next(m.symbols_named(".jump"))
        self.assertEqual(len(list(jump_sym.referent.outgoing_edges)), 4)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_nop_block(self):
        """
        Test that nop_block is correctly recognized, and no fallthrough edge
        to main is created.
        """
        binary = Path("ex")
        with cd(ex_mips_asm_dir / "ex_nop_block"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            main_sym = next(m.symbols_named("main"))
            main_block = main_sym.referent
            inedges = [
                edge
                for edge in main_block.incoming_edges
                if edge.label.type == EdgeType.Fallthrough
            ]
            self.assertEqual(0, len(inedges))

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_switch_overlap(self):
        """
        Test that with two overlapping jumptables, a conherent jump table is
        generated.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_switch_overlap"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
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

        binary = Path("ex")
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
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that the 'add' block has two incoming edges and
            # two outgoing edges.
            add_symbol = next(m.symbols_named("add"))
            assert isinstance(add_symbol.referent, gtirb.CodeBlock)
            add_block = add_symbol.referent
            self.assertEqual(len(list(add_block.outgoing_edges)), 2)
            self.assertEqual(len(list(add_block.incoming_edges)), 2)

            # After the second call we have a call to an external function
            # which appear as a call to the stub in .MIPS.stubs
            return_blocks = [e.target for e in add_block.outgoing_edges]
            next_block = max(return_blocks, key=lambda b: b.address)
            next_block_edges = list(next_block.outgoing_edges)
            self.assertEqual(len(next_block_edges), 2)
            call_edge = [
                edge
                for edge in next_block_edges
                if edge.label.type == EdgeType.Call
            ][0]
            self.assertIsInstance(call_edge.target, gtirb.CodeBlock)
            self.assertEqual(call_edge.target.section.name, ".MIPS.stubs")

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_cfg(self):
        """
        Test ARM32 CFG
        """

        binary = Path("ex")
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
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            sym = next(m.symbols_named("main"))
            block = sym.referent
            self.assertEqual(len(list(block.outgoing_edges)), 2)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_cfg_bx_pc(self):
        """
        Test ARM32 CFG
        """
        binary = Path("ex")
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
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            sym = next(m.symbols_named("main"))
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
        binary = Path("ex")
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
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            main = next(m.symbols_named("main"))
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
            sym = next(m.symbols_named("foo"))
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
        Test ARM32 CFG from TBB/TBH jumptables
        """
        binary = Path("ex")
        examples = (
            ("ex_tbb", b"\xdf\xe8\x00\xf0", 1),
            ("ex_tbh", b"\xdf\xe8\x10\xf0", 2),
            ("ex_tbb_r3_ldr", b"\xd3\xe8\x00\xf0", 1),
            ("ex_tbb_r3_adr", b"\xd3\xe8\x00\xf0", 1),
        )
        for example_dir, jump_instruction_bytes, tbl_entry_size in examples:
            with self.subTest(example_dir=example_dir):
                with cd(ex_arm_asm_dir / example_dir):
                    self.assertTrue(
                        compile(
                            "arm-linux-gnueabihf-gcc",
                            "arm-linux-gnueabihf-g++",
                            "-O0",
                            [],
                            "qemu-arm -L /usr/arm-linux-gnueabihf",
                        )
                    )

                    ir_library = disassemble(
                        binary,
                        strip_exe="arm-linux-gnueabihf-strip",
                        strip=True,
                        extra_strip_flags=["--keep-symbol=table"],
                    ).ir()
                    m = ir_library.modules[0]

                    # Locate the tbb instruction
                    jumping_block = None
                    for block in m.code_blocks:
                        if (
                            block.contents[-len(jump_instruction_bytes) :]
                            == jump_instruction_bytes
                        ):
                            jumping_block = block
                            break
                    else:
                        self.fail("Could not find tbb/tbh instruction")

                    # check that the tbb block has edges to all the jump table
                    # entries
                    self.assertEqual(
                        len(list(jumping_block.outgoing_edges)), 4
                    )
                    # check that there are symbolic expressions for all four
                    # jump table entries
                    if example_dir.startswith("ex_tbb_r3_"):
                        table_sym = next(m.symbols_named("table"))
                        table_address = table_sym.referent.address
                    else:
                        table_address = jumping_block.address + len(
                            jump_instruction_bytes
                        )
                    for i in range(0, 4):
                        symexprs = list(
                            m.symbolic_expressions_at(
                                table_address + i * tbl_entry_size
                            )
                        )
                        self.assertEqual(len(symexprs), 1)

                    # check functionBlocks
                    function_blocks = m.aux_data["functionBlocks"].data
                    for _, blocks in function_blocks.items():
                        if jumping_block in blocks:
                            for edge in jumping_block.outgoing_edges:
                                self.assertIn(edge.target, blocks)
                            break
                    else:
                        self.fail("Jumping block not found in functionBlocks")

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_tbb_zero_entry_cfg(self):
        """
        Test ARM32 CFG for TBB with a zero first entry
        """
        binary = Path("ex")

        with cd(ex_arm_asm_dir / "ex_tbb_zero"):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )

            ir_library = disassemble(
                binary,
                strip_exe="arm-linux-gnueabihf-strip",
                strip=True,
                extra_strip_flags=["--keep-symbol=table"],
            ).ir()

            m = ir_library.modules[0]

            # Locate the tbb instruction
            jumping_block = None
            jump_instruction_bytes = b"\xdf\xe8\x00\xf0"
            for block in m.code_blocks:
                if (
                    block.contents[-len(jump_instruction_bytes) :]
                    == jump_instruction_bytes
                ):
                    jumping_block = block
                    break
            else:
                self.fail("Could not find tbb/tbh instruction")

            # check that the tbb block has edges to all the jump table
            # entries
            self.assertEqual(len(list(jumping_block.outgoing_edges)), 3)
            # check that there are symbolic expressions for jump table entries
            # but not the first one.
            table_address = jumping_block.address + len(jump_instruction_bytes)
            tbl_entry_size = 1
            self.assertEqual(
                len(list(m.symbolic_expressions_at(table_address))), 0
            )
            for i in range(1, 4):
                symexprs = list(
                    m.symbolic_expressions_at(
                        table_address + i * tbl_entry_size
                    )
                )
                self.assertEqual(len(symexprs), 1)

            # check functionBlocks
            function_blocks = m.aux_data["functionBlocks"].data
            for _, blocks in function_blocks.items():
                if jumping_block in blocks:
                    for edge in jumping_block.outgoing_edges:
                        self.assertIn(edge.target, blocks)
                    break
            else:
                self.fail("Jumping block not found in functionBlocks")

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_relative_jump_table3(self):
        """
        Test ARM jumptable with ldr, add, bkpt
        """
        binary = Path("ex")

        with cd(ex_arm_asm_dir / "ex_relative_jump_table3"):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )
            ir_library = disassemble(
                binary,
                strip_exe="arm-linux-gnueabihf-strip",
                strip=True,
            ).ir()
            m = ir_library.modules[0]

            main = next(m.symbols_named("main"))
            main_block = main.referent
            jump_block = next(
                edge
                for edge in main_block.outgoing_edges
                if edge.label.type == EdgeType.Fallthrough
            ).target

            self.assertEqual(len(list(jump_block.outgoing_edges)), 4)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_64_object_cfg(self):
        """
        Test X86_64 object file relocation edges.
        """
        binary = Path("ex.o")
        with cd(ex_dir / "ex1"):
            self.assertTrue(compile("gcc", "g++", "-O0", ["--save-temps"]))
            ir_library = disassemble(binary).ir()
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
        binary = Path("ex")
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
            ir_library = disassemble(
                binary,
                strip_exe="arm-linux-gnueabihf-strip",
                strip=True,
            ).ir()

            # ldrls pc, [pc, r0, LSL2]
            insn = b"\x00\xf1\x9f\x97"

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

    def check_edges(
        self,
        module: gtirb.Module,
        expected_cfg: Dict[str, List[Tuple[str, gtirb.EdgeLabel]]],
    ) -> None:
        """
        Check that the given gtirb `module` has the expected
        CFG edges captured in `expected_cfg`.

        Each entry in `expected_cfg` is represent a block
        and its outgoing edges. Blocks are identified by their
        associated symbol names. An edge is a tuple with a
        block symbol name and an EdgeLabel.
        """
        for src, edges in expected_cfg.items():
            src_block = next(module.symbols_named(src)).referent
            expected_edges = set()
            for tgt, label in edges:
                tgt_block = next(module.symbols_named(tgt)).referent
                expected_edges.add(gtirb.Edge(src_block, tgt_block, label))
            self.assertSetEqual(
                set(src_block.outgoing_edges),
                expected_edges,
                f"unexpected edges from {src}",
            )

    def check_plt_edges(
        self,
        module: gtirb.Module,
        plt_calls: List[Tuple[str, EdgeLabel, EdgeLabel, str]],
    ) -> None:
        """
        Check that each call represented in `plt_calls` has the right
        sequences of edges that lead to the expected target.

        Each element in `plt_call` is a tuple with a starting
        symbol, two edge labels, and a target symbol.
        """
        for src, edge_label1, edge_label2, tgt in plt_calls:
            src_block = next(module.symbols_named(src)).referent
            edges = [
                edge
                for edge in src_block.outgoing_edges
                if edge.label == edge_label1
            ]
            self.assertEqual(
                len(edges),
                1,
                f"Expected one edge with label {edge_label1} from {src}",
            )
            plt_block = edges[0].target
            self.assertEqual(plt_block.section.name, ".plt")
            edges_plt = [
                edge
                for edge in plt_block.outgoing_edges
                if edge.label == edge_label2
            ]
            self.assertEqual(
                len(edges_plt),
                1,
                f"Expected one edge with label {edge_label2} "
                f"from block at {plt_block.address:0x} called from {src}",
            )
            tgt_block = edges_plt[0].target
            self.assertIn(tgt, [s.name for s in tgt_block.references])

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_jump_and_calls_bin(self):
        """
        Test different kinds of jumps and calls.
        """
        binary = Path("ex")
        ex_cfg_dir = ex_asm_dir / "ex_cfg"
        with cd(ex_cfg_dir):
            self.assertTrue(
                compile(
                    "gcc",
                    "g++",
                    "-O0",
                    [],
                )
            )
            ir = disassemble(binary).ir()
            m = ir.modules[0]

            # Check outgoing edges for each block.
            # src and target blocks are identified with through their symbols.
            expected_cfg = {
                "call_local_direct": [
                    ("fun", EdgeLabel(EdgeType.Call, False, True)),
                    (
                        "call_local_indirect",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_indirect": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_indirect_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_indirect_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_offset",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_offset": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_offset_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_offset_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_load",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_load": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "je_local_direct",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "je_local_direct": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, True, True)),
                    (
                        "jmp_local_direct",
                        EdgeLabel(EdgeType.Fallthrough, True, True),
                    ),
                ],
                "jmp_local_direct": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, True))
                ],
                "jmp_local_indirect": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                "jmp_local_reg": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                "jmp_local_reg_offset": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                # printf does not have a plt entry
                "call_ext_reg_printf": [
                    ("printf", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_indirect_printf",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_ext_indirect_printf": [
                    ("printf", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_reg",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
            }
            self.check_edges(m, expected_cfg)

            # For PLT calls, check that we can traverse a list of edges
            # (passing through the PLT block) and end up in the right block
            # (with the right symbol)
            plt_calls = [
                (
                    "call_ext_reg",
                    EdgeLabel(EdgeType.Call, False, False),
                    EdgeLabel(EdgeType.Branch, False, False),
                    "puts",
                ),
                (
                    "call_ext_indirect",
                    EdgeLabel(EdgeType.Call, False, False),
                    EdgeLabel(EdgeType.Branch, False, False),
                    "puts",
                ),
                (
                    "call_ext_plt",
                    EdgeLabel(EdgeType.Call, False, True),
                    EdgeLabel(EdgeType.Branch, False, False),
                    "puts",
                ),
            ]
            self.check_plt_edges(m, plt_calls)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_jump_and_calls_object(self):
        """
        Test different kinds of jumps and calls in an object file.
        """
        binary = Path("ex_original.o")
        ex_cfg_dir = ex_asm_dir / "ex_cfg"
        with cd(ex_cfg_dir):
            self.assertTrue(
                compile(
                    "gcc",
                    "g++",
                    "-O0",
                    extra_flags=["--save-temps"],
                )
            )
            ir = disassemble(binary).ir()
            m = ir.modules[0]

            # Check outgoing edges for each block.
            # src and target blocks are identified with through their symbols.
            expected_cfg = {
                "call_local_direct": [
                    ("fun", EdgeLabel(EdgeType.Call, False, True)),
                    (
                        "call_local_indirect",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_indirect": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_indirect_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_indirect_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_offset",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_offset": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_offset_pc",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_offset_pc": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_local_reg_load",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_local_reg_load": [
                    ("fun", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "je_local_direct",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "je_local_direct": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, True, True)),
                    (
                        "jmp_local_direct",
                        EdgeLabel(EdgeType.Fallthrough, True, True),
                    ),
                ],
                "jmp_local_direct": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, True))
                ],
                "jmp_local_indirect": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                "jmp_local_reg": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                "jmp_local_reg_offset": [
                    ("jump_target", EdgeLabel(EdgeType.Branch, False, False))
                ],
                "call_ext_reg_printf": [
                    ("printf", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_indirect_printf",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_ext_indirect_printf": [
                    ("printf", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_reg",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_ext_reg": [
                    ("puts", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_indirect",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_ext_indirect": [
                    ("puts", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_ext_plt",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_ext_plt": [
                    ("puts", EdgeLabel(EdgeType.Call, False, True)),
                    (
                        "last",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
            }
            self.check_edges(m, expected_cfg)

    @unittest.skipUnless(
        (
            platform.system() == "Windows"
            and os.environ["VSCMD_ARG_TGT_ARCH"] == "x64"
        ),
        "This test is windows x64 only.",
    )
    def test_pe_api_call(self):
        """
        Test that we create CFG edges to external calls in PE binaries.
        """
        binary = Path("ex.exe")
        with cd(ex_asm_dir / "ex_base_relative0"):
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)
            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            ir = disassemble(binary).ir()
            m = ir.modules[0]

            write_console_sym = list(m.symbols_named("WriteConsoleW"))[0]
            self.assertIsInstance(write_console_sym.referent, gtirb.ProxyBlock)
            incoming_edges = list(write_console_sym.referent.incoming_edges)
            self.assertGreaterEqual(len(incoming_edges), 1)
            for edge in incoming_edges:
                self.assertEqual(edge.label.type, gtirb.EdgeType.Call)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm64_calls(self):
        """
        Test different kinds of calls for arm64.
        """
        binary = Path("ex")
        ex_cfg_dir = ex_arm64_asm_dir / "ex_cfg"
        with cd(ex_cfg_dir):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-g++", "-O0", []
                )
            )
            ir = disassemble(binary).ir()
            m = ir.modules[0]

            # Check outgoing edges for each block.
            # src and target blocks are identified with through their symbols.
            expected_cfg = {
                "call_direct": [
                    ("f", EdgeLabel(EdgeType.Call, False, True)),
                    (
                        "call_direct_external",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_indirect": [
                    ("f", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_indirect_offset",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_indirect_offset": [
                    ("g", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "call_indirect_external",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
                "call_indirect_external": [
                    ("puts", EdgeLabel(EdgeType.Call, False, False)),
                    (
                        "final",
                        EdgeLabel(EdgeType.Fallthrough, False, True),
                    ),
                ],
            }
            self.check_edges(m, expected_cfg)

            plt_calls = [
                (
                    "call_direct_external",
                    EdgeLabel(EdgeType.Call, False, True),
                    EdgeLabel(EdgeType.Branch, False, False),
                    "puts",
                )
            ]
            self.check_plt_edges(m, plt_calls)


if __name__ == "__main__":
    unittest.main()
