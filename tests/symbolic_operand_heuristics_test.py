import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_asm_dir = Path("./examples/") / "asm_examples"


class SymbolicOperandsTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lea_results(self):
        """
        Test that
         - LEA is always symbolized when it is a PC-relative
         - Other LEA operation might be used for normal arithmetic
           If the result is compared to a non-symbolic operand or
           multiplied, the negative heuristic will prevent symbolization.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_symbolic_operand_heuristics"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that we symbolize the LEA instructions with 0 offset
            symbolized = [
                "rip_lea",
                "rip_lea_misleading",
                "rip_lea_misleading_call_rdi",
                "rip_lea_misleading_call_rdx",
            ]
            for name in symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                _, _, sym_expr = next(
                    block.byte_interval.symbolic_expressions_at(
                        range(block.address, block.address + block.size)
                    )
                )
                self.assertIsInstance(sym_expr, gtirb.SymAddrConst)
                self.assertEqual(sym_expr.offset, 0)
            # check that we don't symbolize LEA instructions used for
            # regular arithmetic
            not_symbolized = ["lea_multiplied", "lea_cmp"]
            for name in not_symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                self.assertFalse(
                    list(
                        block.byte_interval.symbolic_expressions_at(
                            range(block.address, block.address + block.size)
                        )
                    )
                )


if __name__ == "__main__":
    unittest.main()
