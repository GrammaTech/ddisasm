import platform
import sys
import unittest
from pathlib import Path

import gtirb

from check_gtirb import lookup_sym
from disassemble_reassemble_check import compile, disassemble, cd
from gtirb.cfg import EdgeType

ex_dir = Path("./examples/")


class TestUnpopulatedJumpTable(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_jumptable_fallthrough_edge(self):
        with cd(ex_dir / "ex_switch"):
            self.assertTrue(
                compile("clang", "", "-O0", ["-m32", "-fno-pie", "-no-pie"])
            )

            binary = Path("ex")
            ex_ir = disassemble(binary).ir()
            module = ex_ir.modules[0]

            # Find the function with the jump table.
            fun_sym = next(sym for sym in module.symbols if sym.name == "fun")
            fun_block = fun_sym.referent
            self.assertIsInstance(fun_block, gtirb.CodeBlock)

            def fallthrough_from(block, *, n=1):
                """Fall through from BLOCK, N times."""
                while n > 0:
                    fallthrough_edges = [
                        edge
                        for edge in block.outgoing_edges
                        if edge.label.type == EdgeType.Fallthrough
                    ]
                    self.assertEqual(1, len(fallthrough_edges))
                    block = fallthrough_edges[0].target
                    n = n - 1
                return block

            block = fallthrough_from(fun_block, n=3)
            target_syms = [
                lookup_sym(edge.target) for edge in block.outgoing_edges
            ]
            self.assertEqual(4, len(target_syms))
            # Check that there are edges to the functions.
            dest_set = set()
            for edge1 in block.outgoing_edges:
                for edge2 in edge1.target.outgoing_edges:
                    dest_set.add(lookup_sym(edge2.target))
            self.assertTrue({"one", "two", "three", "four"}.issubset(dest_set))


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
