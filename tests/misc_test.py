import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"


class LibrarySymbolsTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_symbols_through_plt(self):
        """
        Test a library that calls local methods through
        the plt table and locally defined symbols
        do not point to proxy blocks.
        """

        library = "ex.so"
        with cd(ex_dir / "ex_lib_symbols"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(
                disassemble(
                    library,
                    "strip",
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                )
            )

            ir_library = gtirb.IR.load_protobuf(library + ".gtirb")
            m = ir_library.modules[0]

            # foo is a symbol pointing to a code block
            foo = [s for s in m.symbols if s.name == "foo"][0]
            assert isinstance(foo.referent, gtirb.CodeBlock)

            # bar calls through the plt
            bar = [s for s in m.symbols if s.name == "bar"][0]
            bar_block = bar.referent
            callee = [
                e.target
                for e in bar_block.outgoing_edges
                if e.label.type == gtirb.Edge.Type.Call
            ][0]
            assert [s.name for s in m.sections_on(callee.address)][0] in [
                ".plt",
                ".plt.sec",
            ]


class AuxDataTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_cfi_table(self):
        """
        Test that cfi directives are correctly generated.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_cfi_directives"):
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
            cfi = m.aux_data["cfiDirectives"].data
            # we simplify directives to make queries easier

            found = False
            for offset, directives in cfi.items():
                directive_names = [elem[0] for elem in directives]
                if ".cfi_remember_state" in directive_names:
                    found = True
                    # the directive is at the end of the  block
                    assert offset.element_id.size == offset.displacement
                    assert directive_names == [
                        ".cfi_remember_state",
                        ".cfi_restore_state",
                        ".cfi_endproc",
                    ]
                    break
            assert found


class MovedLabelTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_moved_label(self):
        """
        Test that labels are correctly moved.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_moved_label"):
            self.assertTrue(compile("gcc", "g++", "-Os", []))
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

            symbol_of_interest = [s for s in m.symbols if s.name == "point.1"][
                0
            ]
            assert isinstance(symbol_of_interest.referent, gtirb.CodeBlock)

            block = symbol_of_interest.referent
            bi = block.byte_interval
            sexpr = set(
                bi.symbolic_expressions_at(
                    range(block.address, block.address + block.size)
                )
            )
            self.assertEqual(len(sexpr), 1)
            se1 = next(iter(sexpr))[2]
            assert isinstance(se1, gtirb.SymAddrConst)
            self.assertEqual(se1.symbol.name, "point.2")
            self.assertEqual(se1.offset, 22)


if __name__ == "__main__":
    unittest.main()
