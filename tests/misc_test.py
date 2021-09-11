import os
import platform
import unittest
import subprocess
from disassemble_reassemble_check import (
    compile,
    cd,
    disassemble,
    reassemble,
    test,
    make,
)
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

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_souffle_relations(self):
        """Test `--with-souffle-relations' equivalence to `--debug-dir'."""

        with cd(ex_dir / "ex1"):
            # build
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # disassemble
            if not os.path.exists("dbg"):
                os.mkdir("dbg")
            self.assertTrue(
                disassemble(
                    "ex",
                    False,
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                    extra_args=[
                        "-F",
                        "--with-souffle-relations",
                        "--debug-dir",
                        "dbg",
                    ],
                )
            )

            # load the gtirb
            ir = gtirb.IR.load_protobuf("ex.gtirb")
            m = ir.modules[0]

            # dump relations to directory
            if not os.path.exists("aux"):
                os.mkdir("aux")
            for table, ext in [
                ("souffleFacts", "facts"),
                ("souffleOutputs", "csv"),
            ]:
                for name, relation in m.aux_data[table].data.items():
                    _, csv = relation
                    with open(f"aux/{name}.{ext}", "w") as out:
                        out.write(csv)

            # compare the relations directories
            subprocess.check_call(["diff", "dbg", "aux"])


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


class RawGtirbTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_read_gtirb(self):

        binary = "ex"
        with cd(ex_dir / "ex1"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # Output GTIRB file without disassembling.
            self.assertTrue(
                disassemble(
                    binary,
                    False,
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                    extra_args=["--no-analysis"],
                )
            )

            # Disassemble GTIRB input file.
            self.assertTrue(
                disassemble(
                    "ex.gtirb",
                    False,
                    False,
                    False,
                    format="--asm",
                    extension="s",
                )
            )

            self.assertTrue(reassemble("gcc", "ex.gtirb", extra_flags=[]))
            self.assertTrue(test())


class DataDirectoryTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_data_directories_in_code(self):
        with cd(ex_dir / "ex1"):

            # Compile with `.rdata' section merged to `.text'.
            proc = subprocess.run(
                ["cl", "/Od", "ex.c", "/link", "/merge:.rdata=.text"],
                stdout=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 0)

            # Disassemble to GTIRB file.
            self.assertTrue(
                disassemble(
                    "ex.exe",
                    False,
                    False,
                    False,
                    format="--ir",
                    extension="gtirb",
                    extra_args=[],
                )
            )

            # Load the GTIRB file.
            ir = gtirb.IR.load_protobuf("ex.exe.gtirb")
            module = ir.modules[0]

            def is_code(section):
                return gtirb.ir.Section.Flag.Executable in section.flags

            pe_data_directories = module.aux_data["peDataDirectories"].data
            code_blocks = [
                (b.address, b.address + b.size) for b in module.code_blocks
            ]
            for _, addr, size in pe_data_directories:
                # Check data directories in code sections are data blocks.
                if size > 0:
                    if any(s for s in module.sections_on(addr) if is_code(s)):
                        data_block = next(module.data_blocks_on(addr), None)
                        self.assertIsNotNone(data_block)

                # Check no code blocks were created within data directories.
                for start, end in code_blocks:
                    self.assertFalse(start <= addr <= end)


class PeResourcesTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_generate_resources(self):
        with cd(ex_dir / "ex_rsrc"):
            # Build example with PE resource file.
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            # Disassemble to GTIRB file.
            self.assertTrue(
                disassemble(
                    "ex.exe",
                    False,
                    False,
                    False,
                    format="--asm",
                    extension="s",
                    extra_args=[
                        "--generate-import-libs",
                        "--generate-resources",
                    ],
                )
            )

            # Reassemble with regenerated RES file.
            self.assertTrue(
                reassemble(
                    "ml64",
                    "ex.exe",
                    extra_flags=[
                        "/link",
                        "ex.res",
                        "/entry:__EntryPoint",
                        "/subsystem:console",
                    ],
                )
            )

            proc = subprocess.run(make("check"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
