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

if platform.system() == "Linux":
    import lief

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
            self.assertTrue(disassemble(library, format="--ir")[0])

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


class IFuncSymbolsTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_symbols_through_plt(self):
        """
        Test a binary that calls a local method defined as
        gnu_indirect_function through plt and check if the local symbol is
        chosen over global symbols.
        """

        binary = "ex.so"
        with cd(ex_asm_dir / "ex_ifunc"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--asm")[0])
            self.assertTrue(
                reassemble(
                    "gcc",
                    binary,
                    extra_flags=[
                        "-shared",
                        "-Wl,--version-script=ex.map",
                        "-nostartfiles",
                    ],
                )
            )

            binlief = lief.parse(binary)
            for relocation in binlief.relocations:
                # The rewritten binary should not contain any JUMP_SLOT
                # relocation: the relocation for strcmp should be
                # R_X86_64_IRELATIVE instead of R_X86_64_JUMP_SLOT.
                self.assertTrue(
                    lief.ELF.RELOCATION_X86_64(relocation.type)
                    != lief.ELF.RELOCATION_X86_64.JUMP_SLOT
                )


class OverlappingInstructionTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lock_cmpxchg(self):
        """
        Test a binary that contains legitimate overlapping instructions:
        e.g., 0x0: lock cmpxchg
        At 0x0, lock cmpxchg
        At 0x1,      cmpxchg
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_overlapping_instruction"):

            self.assertTrue(compile("gcc", "g++", "-O0", []))
            gtirb_file = "ex.gtirb"
            self.assertTrue(disassemble(binary, gtirb_file, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(gtirb_file)
            m = ir_library.modules[0]

            main_sym = next(sym for sym in m.symbols if sym.name == "main")
            main_block = main_sym.referent
            self.assertIsInstance(main_block, gtirb.CodeBlock)
            self.assertEqual(len(list(main_block.outgoing_edges)), 1)


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
            self.assertTrue(disassemble(binary, format="--ir")[0])

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
            self.assertTrue(found)

            # check that we move misaligned directives to function start
            bar_symbol = list(m.symbols_named("bar"))[0]
            bar_block = bar_symbol.referent
            self.assertIsNotNone(bar_block)
            cfi_at_bar_start = [
                directive[0] for directive in cfi[gtirb.Offset(bar_block, 0)]
            ]
            self.assertIn(".cfi_startproc", cfi_at_bar_start)

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
                    format="--ir",
                    extra_args=[
                        "-F",
                        "--with-souffle-relations",
                        "--debug-dir",
                        "dbg",
                    ],
                )[0]
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
                    dirname, filename = name.split(".", 1)
                    _, csv = relation
                    path = Path("aux", dirname, f"{filename}.{ext}")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with open(path, "w") as out:
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
            self.assertTrue(disassemble(binary, format="--ir")[0])

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
                    binary, format="--ir", extra_args=["--no-analysis"]
                )[0]
            )

            # Disassemble GTIRB input file.
            self.assertTrue(disassemble("ex.gtirb", format="--asm")[0])

            self.assertTrue(
                reassemble("gcc", "ex.gtirb", extra_flags=["-nostartfiles"])
            )
            self.assertTrue(test())


class DataDirectoryTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_data_directories_in_code(self):
        with cd(ex_dir / "ex1"):
            subprocess.run(make("clean"), stdout=subprocess.DEVNULL)

            # Compile with `.rdata' section merged to `.text'.
            proc = subprocess.run(
                ["cl", "/Od", "ex.c", "/link", "/merge:.rdata=.text"],
                stdout=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 0)

            # Disassemble to GTIRB file.
            self.assertTrue(disassemble("ex.exe", format="--ir")[0])

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
                    format="--asm",
                    extra_args=[
                        "--generate-import-libs",
                        "--generate-resources",
                    ],
                )
            )

            # Reassemble with regenerated RES file.
            ml, entry = "ml64", "__EntryPoint"
            if os.environ.get("VSCMD_ARG_TGT_ARCH") == "x86":
                ml, entry = "ml", "_EntryPoint"
            self.assertTrue(
                reassemble(
                    ml,
                    "ex.exe",
                    extra_flags=[
                        "/link",
                        "ex.res",
                        "/entry:" + entry,
                        "/subsystem:console",
                    ],
                )
            )

            proc = subprocess.run(make("check"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)


class SymbolSelectionTests(unittest.TestCase):
    def check_first_sym_expr(
        self, m: gtirb.Module, block_name: str, target_name: str
    ) -> None:
        """
        Check that the first Symexpr in a block identified
        with symbol 'block_name' points to a symbol with
        name 'target_name'
        """
        sym = next(s for s in m.symbols if s.name == block_name)
        self.assertIsInstance(sym.referent, gtirb.CodeBlock)
        block = sym.referent
        sexpr = sorted(
            [
                t[1:]
                for t in block.byte_interval.symbolic_expressions_at(
                    range(block.address, block.address + block.size)
                )
            ]
        )[0]
        self.assertEqual(sexpr[1].symbol.name, target_name)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_symbol_selection(self):
        """
        Test that the right symbols are chosen for relocations
        and for functions.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_symbol_selection"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            self.check_first_sym_expr(m, "Block_hello", "hello_not_hidden")
            self.check_first_sym_expr(m, "Block_how", "how_global")
            self.check_first_sym_expr(m, "Block_bye", "bye_obj")

            # check symbols at the end of sections
            syms = [
                s
                for s in m.symbols
                if s.name
                in ["__init_array_end", "end_of_data_section", "edata", "_end"]
            ]
            self.assertTrue(all(s.at_end for s in syms))

            # check chosen function names
            fun_names = {
                sym.name for sym in m.aux_data["functionNames"].data.values()
            }
            self.assertIn("fun", fun_names)
            self.assertNotIn("_fun", fun_names)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_boundary_sym_expr(self):
        """
        Test that symexpr that should be pointing
        to the end of a section indeed points to
        the symbol at the end of the section.
        """

        binary = "ex"
        with cd(ex_asm_dir / "ex_boundary_sym_expr"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir")[0])
            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]
            self.check_first_sym_expr(m, "load_end", "nums_end")


class ElfSymbolVersionsTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_symbol_versions(self):
        """
        Test that symbols have the right version.
        """

        binary = "libfoo.so"
        with cd(ex_dir / "ex_symver"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(disassemble(binary, format="--ir")[0])

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            (defs, needed, symver_entries) = m.aux_data[
                "elfSymbolVersions"
            ].data

            # The version of the library itself is recorded in defs
            # This is typically SymbolVersionId = 1 (but I am not sure if it's
            # required by the spec to be)
            VER_FLG_BASE = 0x1
            self.assertIn((["libfoo.so"], VER_FLG_BASE), defs.values())

            foo_symbols = sorted(
                [sym for sym in m.symbols if sym.name == "foo"],
                key=lambda x: x.referent.address,
            )
            self.assertEqual(len(foo_symbols), 3)

            foo1, foo2, foo3 = foo_symbols
            # Symbols have the right versions
            self.assertEqual(
                defs[symver_entries[foo1][0]], (["LIBFOO_1.0"], 0)
            )
            self.assertEqual(
                defs[symver_entries[foo2][0]],
                (["LIBFOO_2.0", "LIBFOO_1.0"], 0),
            )
            self.assertEqual(
                defs[symver_entries[foo3][0]],
                (["LIBFOO_3.0", "LIBFOO_2.0"], 0),
            )

            # Check that foo@LIBFOO_1.0 and foo@LIBFOO_2.0 are not default
            self.assertTrue(symver_entries[foo1][1])
            self.assertTrue(symver_entries[foo2][1])
            self.assertFalse(symver_entries[foo3][1])

            bar_symbols = [sym for sym in m.symbols if sym.name == "bar"]

            bar1, bar2 = bar_symbols
            # Check needed symbol versions
            needed_versions = {
                needed["libbar.so"][symver_entries[bar1][0]],
                needed["libbar.so"][symver_entries[bar2][0]],
            }
            self.assertEqual(needed_versions, {"LIBBAR_1.0", "LIBBAR_2.0"})
            # Needed versions are not hidden
            self.assertFalse(symver_entries[bar1][1])
            self.assertFalse(symver_entries[bar2][1])


class OverlayTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_pe_overlay(self):
        with cd(ex_dir / "ex1"):
            # Create binary with overlay data.
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            # Append bytes to the binary.
            with open("ex.exe", "a") as pe:
                pe.write("OVERLAY")

            # Disassemble to GTIRB file.
            self.assertTrue(disassemble("ex.exe", format="--ir")[0])

            # Check overlay aux data.
            ir = gtirb.IR.load_protobuf("ex.exe.gtirb")
            module = ir.modules[0]
            overlay = module.aux_data["overlay"].data
            self.assertEqual(bytes(overlay), b"OVERLAY")

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_linux_overlay(self):
        with cd(ex_dir / "ex1"):
            # Create binary with overlay data.
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            # Append bytes to the binary.
            with open("ex", "a") as binary:
                binary.write("OVERLAY")

            # Disassemble to GTIRB file.
            self.assertTrue(disassemble("ex", format="--ir")[0])

            # Check overlay aux data.
            ir = gtirb.IR.load_protobuf("ex.gtirb")
            module = ir.modules[0]
            overlay = module.aux_data["overlay"].data
            self.assertEqual(bytes(overlay), b"OVERLAY")


if __name__ == "__main__":
    unittest.main()
