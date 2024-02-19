import platform
import unittest
from disassemble_reassemble_check import (
    compile,
    cd,
    disassemble,
)
from pathlib import Path
import gtirb

ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"


class MovedLabelTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_moved_label(self):
        """
        Test that labels are correctly moved.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_moved_label"):
            self.assertTrue(compile("gcc", "g++", "-Os", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            symbol_of_interest = next(m.symbols_named("point.1"))
            self.assertIsInstance(symbol_of_interest.referent, gtirb.CodeBlock)

            block = symbol_of_interest.referent
            bi = block.byte_interval
            sexpr = set(
                bi.symbolic_expressions_at(
                    range(block.address, block.address + block.size)
                )
            )
            self.assertEqual(len(sexpr), 1)
            se1 = next(iter(sexpr))[2]
            self.assertIsInstance(se1, gtirb.SymAddrConst)
            self.assertEqual(se1.symbol.name, "array_end")
            self.assertEqual(se1.offset, 0)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_moved_label_imm(self):
        """
        Test different kinds of moved label immediates
        and boundary symbolic expressions.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_moved_label_imm"):
            self.assertTrue(compile("gcc", "g++", "-Os", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # Code block symbol, sym expr index, data section, non-zero offset
            expected_sym_exprs = [
                ("print", 0, ".data", False),
                ("print_descending", 0, ".data", False),
                ("print_descending_mov", 0, ".data", False),
                ("loop_back_above", 0, ".data", True),
                ("loop_back_below", 0, ".data2", True),
                ("print_above_mov", 0, ".data", True),
                ("print_above_loaded_pc", 0, ".data", True),
                ("print_below_ascending", 0, ".data2", True),
                ("print_below_ascending_pc", 0, ".data2", True),
                ("print_above_descending", 0, ".data", True),
            ]
            for (
                block_name,
                index,
                data_section,
                non_zero_offset,
            ) in expected_sym_exprs:

                block = next(m.symbols_named(block_name)).referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                sym_expr_elem = list(
                    m.symbolic_expressions_at(
                        range(block.address, block.address + block.size)
                    )
                )[index]
                sym_expr = sym_expr_elem[2]
                self.assertIsInstance(sym_expr, gtirb.SymAddrConst)
                tgt_sym = sym_expr.symbol
                self.assertEqual(
                    tgt_sym.referent.section.name,
                    data_section,
                    f"Expected symbolic expression in {block_name}"
                    f" to point to section {data_section}",
                )
                if non_zero_offset:
                    self.assertFalse(
                        sym_expr.offset == 0,
                        f"Expected symbolic expresssion in {block_name}"
                        " to have non-zero offset",
                    )
                else:
                    self.assertEqual(
                        sym_expr.offset,
                        0,
                        f"Expected symbolic expression in {block_name} "
                        f"to have zero offset. Offset {sym_expr.offset} found",
                    )


if __name__ == "__main__":
    unittest.main()
