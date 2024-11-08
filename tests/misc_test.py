import os
import platform
import unittest
import re
import subprocess
from disassemble_reassemble_check import (
    binary_print,
    compile,
    cd,
    disassemble,
    test,
    make,
)
from pathlib import Path
from typing import Optional, Tuple
from gtirb.cfg import EdgeType
from gtirb.symbolicexpression import SymbolicExpression
import gtirb
import lief

from tests.snippets import parse_souffle_output

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

        library = Path("ex.so")
        with cd(ex_dir / "ex_lib_symbols"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(library).ir()
            m = ir_library.modules[0]

            # foo is a symbol pointing to a code block
            foo = next(m.symbols_named("foo"))
            assert isinstance(foo.referent, gtirb.CodeBlock)

            # bar calls through the plt
            bar = next(m.symbols_named("bar"))
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
    def test_gnu_indirect_function(self):
        """
        Test a binary that calls a local method defined as
        gnu_indirect_function through plt and check if the local symbol is
        chosen over global symbols.
        """

        binary = Path("ex.so")
        with cd(ex_asm_dir / "ex_ifunc"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            result = disassemble(binary)
            binary_print(result.ir_path, binary)

            binlief = lief.parse(str(binary))
            for relocation in binlief.relocations:
                # The rewritten binary should not contain any JUMP_SLOT
                # relocation: the relocation for strcmp should be
                # R_X86_64_IRELATIVE instead of R_X86_64_JUMP_SLOT.
                self.assertTrue(
                    lief.ELF.RELOCATION_X86_64(relocation.type)
                    != lief.ELF.RELOCATION_X86_64.JUMP_SLOT
                )


class OverlappingInstructionTests(unittest.TestCase):
    def subtest_lock_cmpxchg(self, example: str):
        """
        Subtest body for test_lock_cmpxchg
        """
        binary = Path("ex")
        self.assertTrue(compile("gcc", "g++", "-O0", []))
        ir_path = Path("ex.gtirb")
        disassemble(binary, ir_path)

        ir_library = gtirb.IR.load_protobuf(ir_path)
        m = ir_library.modules[0]

        main_sym = next(m.symbols_named("main"))
        main_block = main_sym.referent

        self.assertIsInstance(main_block, gtirb.CodeBlock)

        # find the lock cmpxchg instruction - ensure it exists and is
        # reachable from main
        block = main_block
        inst_prefix_op = b"\xf0\x48\x0f\xb1"
        fallthru_count = 0
        fallthru_max = 5
        blocks = [main_block]
        while block.contents[: len(inst_prefix_op)] != inst_prefix_op:
            if fallthru_count == fallthru_max:
                trace = " -> ".join([hex(b.address) for b in blocks])
                msg = "exceeded max fallthru searching for lock cmpxchg: {}"
                self.fail(msg.format(trace))
            try:
                block = next(
                    e
                    for e in block.outgoing_edges
                    if e.label.type == gtirb.Edge.Type.Fallthrough
                ).target
            except StopIteration:
                self.fail("lock cmpxchg is not a code block")

            self.assertIsInstance(block, gtirb.CodeBlock)
            blocks.append(block)
            fallthru_count += 1

        self.assertEqual(len(list(block.incoming_edges)), 1)

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
        examples = (
            "ex_overlapping_instruction",
            "ex_overlapping_instruction_2",
            "ex_overlapping_instruction_3",
        )

        for example in examples:
            with self.subTest(example=example), cd(ex_asm_dir / example):
                self.subtest_lock_cmpxchg(example)


def check_avx512f_support():
    if platform.system() == "Linux":
        output = subprocess.check_output(["lscpu"])
        output = output.decode("utf-8")
        if "avx512f" in output:
            return True
    return False


class AuxDataTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_cfi_table(self):
        """
        Test that cfi directives are correctly generated.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_cfi_directives"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
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

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_dyn_shared(self):
        """
        Test that binary types for DYN SHARED are correctly generated.
        """
        binary = Path("fun.so")
        with cd(ex_dir / "ex_dyn_library"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]
            dyn = m.aux_data["binaryType"].data

            self.assertIn("DYN", dyn)
            self.assertIn("SHARED", dyn)
            self.assertNotIn("PIE", dyn)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_dyn_pie(self):
        """
        Test that binary types for DYN PIE are correctly generated.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_plt_nop"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]
            dyn = m.aux_data["binaryType"].data

            self.assertIn("DYN", dyn)
            self.assertIn("PIE", dyn)
            self.assertNotIn("SHARED", dyn)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_dyn_none(self):
        """
        Test that binary types for non-DYN are correctly generated.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_moved_label"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]
            dyn = m.aux_data["binaryType"].data

            self.assertIn("EXEC", dyn)
            self.assertNotIn("DYN", dyn)
            self.assertNotIn("PIE", dyn)
            self.assertNotIn("SHARED", dyn)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_misaligned_fde(self):
        """
        Test that misaligned_fde_start is correctly generated.
        """
        binary = Path("ex")
        modes = [
            False,  # no strip
            True,  # strip
        ]

        for mode in modes:
            with self.subTest(mode=mode):
                with cd(ex_asm_dir / "ex_misaligned_fde"):
                    self.assertTrue(compile("gcc", "g++", "-O0", []))
                    ir_library = disassemble(binary, strip=mode).ir()
                    m = ir_library.modules[0]

                    main_sym = next(m.symbols_named("main"))
                    main_block = main_sym.referent
                    outedges = [
                        edge
                        for edge in main_block.outgoing_edges
                        if edge.label.type == EdgeType.Fallthrough
                    ]
                    self.assertEqual(1, len(outedges))
                    block = outedges[0].target
                    # LEA should have a symbolic expression.
                    # If `bar` is not recognized as misaligned_fde_start,
                    # the LEA will be missing a symbolic expression.
                    self.assertTrue(
                        list(
                            m.symbolic_expressions_at(
                                range(
                                    block.address, block.address + block.size
                                )
                            )
                        )
                    )

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
            ir = disassemble(
                Path("ex"),
                extra_args=[
                    "-F",
                    "--with-souffle-relations",
                    "--debug-dir",
                    "dbg",
                ],
            ).ir()

            # load the gtirb
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

    def assert_regex_match(self, text, pattern):
        """
        Like unittest's assertRegex, but also return the match object on
        success.

        assertRegex provides a nice output on failure, but doesn't return the
        match object, so we assert, and then search.
        """
        compiled = re.compile(pattern)
        self.assertRegex(text, compiled)
        return re.search(compiled, text)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_dynamic_init_fini(self):
        """
        Test generating auxdata from DT_INIT and DT_FINI dynamic entries
        """
        binary = Path("ex")
        with cd(ex_dir / "ex_dynamic_initfini"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # Ensure INIT / FINI are present (so that this breaks if compiler
            # behavior changes in the future)
            readelf = subprocess.run(
                ["readelf", "--dynamic", binary],
                check=True,
                capture_output=True,
                text=True,
            )
            template = r"0x[0-9a-f]+\s+\({}\)\s+(0x[0-9a-f]+)"
            init_match = self.assert_regex_match(
                readelf.stdout, template.format("INIT")
            )
            fini_match = self.assert_regex_match(
                readelf.stdout, template.format("FINI")
            )

            ir = disassemble(binary).ir()
            m = ir.modules[0]
            init = m.aux_data["elfDynamicInit"].data
            fini = m.aux_data["elfDynamicFini"].data

            self.assertIsInstance(init, gtirb.CodeBlock)
            self.assertIsInstance(fini, gtirb.CodeBlock)

            self.assertEqual(int(init_match.group(1), 16), init.address)
            self.assertEqual(int(fini_match.group(1), 16), fini.address)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_size(self):
        """
        Test that a PT_GNU_STACK segment with size populates elfStackSize
        """
        binary = Path("ex")
        with cd(ex_dir / "ex1"):
            stack_size = 0x200000
            self.assertTrue(
                compile(
                    "gcc", "g++", "-O0", [f"-Wl,-z,stack-size={stack_size}"]
                )
            )
            ir = disassemble(binary).ir()
            m = ir.modules[0]

            self.assertEqual(m.aux_data["elfStackSize"].data, stack_size)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_exec(self):
        """
        Test that a PT_GNU_STACK segment populates correct executable flags
        """
        cases = (
            ("execstack", True),
            ("noexecstack", False),
        )

        for ld_keyword, is_exec in cases:
            binary = Path("ex")
            with self.subTest(keyword=ld_keyword), cd(ex_dir / "ex1"):
                self.assertTrue(
                    compile("gcc", "g++", "-O0", [f"-Wl,-z,{ld_keyword}"])
                )
                ir = disassemble(binary).ir()
                m = ir.modules[0]

                # verify executable bit
                self.assertEqual(m.aux_data["elfStackExec"].data, is_exec)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_soname(self):
        """
        Test SONAME dynamic-section entry
        """
        binary = "ex.so"
        with cd(ex_asm_dir / "ex_ifunc"):
            self.assertTrue(
                compile("gcc", "g++", "-O0", [f"-Wl,-soname={binary}"])
            )
            ir = disassemble(Path(binary)).ir()
            m = ir.modules[0]

            self.assertEqual(m.aux_data["elfSoname"].data, binary)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_aligned_data_in_code(self):
        """
        Test that alignment directives are correctly generated for
        data_in_code referenced by instructions that require aligned memory.
        """
        binary = "ex"
        with cd(ex_asm_dir / "ex_aligned_data_in_code"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir = disassemble(Path(binary)).ir()
            m = ir.modules[0]

            main_sym = next(m.symbols_named("main"))
            main_block = main_sym.referent

            alignments = m.aux_data["alignment"].data.items()
            alignment_list = [
                alignment
                for block, alignment in alignments
                if (
                    block.address > main_block.address
                    and block in m.data_blocks
                )
            ]

            # alignment=16: `data128.1`, `data128.2`
            self.assertEqual(alignment_list.count(16), 2)
            # alignment=32: `data256`
            self.assertEqual(alignment_list.count(32), 1)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    @unittest.skipUnless(
        check_avx512f_support(), "This test requires avx512f."
    )
    def test_aligned_data_in_code_avx512f(self):
        """
        Test that alignment directives are correctly generated for
        data_in_code referenced by instructions that require 64-byte
        alignment
        """
        binary = "ex"
        with cd(ex_asm_dir / "ex_aligned_data_in_code_avx512f"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir = disassemble(Path(binary)).ir()
            m = ir.modules[0]

            main_sym = next(m.symbols_named("main"))
            main_block = main_sym.referent

            alignments = m.aux_data["alignment"].data.items()
            alignment_list = [
                alignment
                for block, alignment in alignments
                if block.address > main_block.address
            ]

            # alignment=64: `data512`
            self.assertEqual(alignment_list.count(64), 1)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_func_align(self):
        """
        Test that alignment directives are correctly generated for functions.
        """
        binary = "ex"
        with cd(ex_dir / "ex_memberFunction"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir = disassemble(Path(binary)).ir()
            m = ir.modules[0]

            funcs = ["_ZN1a3fooEv", "_ZN1a3barEv", "_ZN1a3bazEv"]
            #        -------------  -------------  -------------
            #           global          local          weak

            func_blocks = [
                next(m.symbols_named(sym)).referent for sym in funcs
            ]

            alignments = m.aux_data["alignment"].data

            self.assertTrue(all(b in alignments for b in func_blocks))


class RawGtirbTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_read_gtirb(self):
        binary = Path("ex")
        with cd(ex_dir / "ex1"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # Output GTIRB file without disassembling.
            ir_path = "ex.gtirb"
            ir_path_analyzed = "ex_analyzed.gtirb"
            disassemble(binary, extra_args=["--no-analysis"], output=ir_path)

            # Disassemble GTIRB input file.
            disassemble(ir_path, output=ir_path_analyzed)

            binary_print(ir_path_analyzed, binary)
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
            ir = disassemble(Path("ex.exe")).ir()
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
            binary_path = Path("ex.exe")
            ir_path = Path("ex.gtirb")
            disassemble(binary_path, output=ir_path)

            binary_print(ir_path, binary_path)

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
        sym = next(m.symbols_named(block_name))
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

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_symbol_selection"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            self.check_first_sym_expr(m, "Block_hello", "hello_local")
            self.check_first_sym_expr(m, "Block_how", "how_global")
            self.check_first_sym_expr(m, "Block_bye", "bye_obj")

            # check symbols at the end of sections
            syms = []
            for s in [
                "__init_array_end",
                "end_of_data_section",
                "edata",
                "_end",
            ]:
                syms += m.symbols_named(s)
            self.assertTrue(all(s.at_end for s in syms))

            # check chosen function names
            fun_names = {
                sym.name for sym in m.aux_data["functionNames"].data.values()
            }
            self.assertIn("fun", fun_names)
            self.assertNotIn("_fun", fun_names)

    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only"
    )
    def test_pe_function_symbol_selection(self):
        """
        Test that function names are correctly selected
        in PE binaries.
        """
        library = Path("baz.dll")
        with cd(ex_dir / "ex_ml_sym_mangling"):
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)
            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)
            for extra_args in ([], ["-F"]):
                with self.subTest(extra_args=extra_args):
                    ir_library = disassemble(
                        library, extra_args=extra_args
                    ).ir()
                    m = ir_library.modules[0]

                    # check chosen function names
                    fun_names = {
                        sym.name
                        for sym in m.aux_data["functionNames"].data.values()
                    }
                    self.assertIn("Baz", fun_names)
                    self.assertIn("_Baz", fun_names)
                    self.assertIn("__Baz", fun_names)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_boundary_sym_expr(self):
        """
        Test that symexpr that should be pointing
        to the end of a section indeed points to
        the symbol at the end of the section.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_boundary_sym_expr"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]
            self.check_first_sym_expr(m, "load_end", "nums_end")


class ElfSymbolAuxdataTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lib_symbol_versions(self):
        """
        Test that symbols have the right version.
        """

        binary = Path("libfoo.so")
        with cd(ex_dir / "ex_symver"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
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
                m.symbols_named("foo"),
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

            bar_symbols = m.symbols_named("bar")

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

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_copy_symbol_versions(self):
        def lookup_sym_ver_need(
            symbol: gtirb.Symbol,
        ) -> Optional[Tuple[str, str]]:
            """
            Get the library and version for a needed symbol
            """
            _, ver_needs, ver_entries = m.aux_data["elfSymbolVersions"].data

            ver_id, hidden = ver_entries[symbol]
            for lib, lib_ver_needs in ver_needs.items():
                if ver_id in lib_ver_needs:
                    return (lib, lib_ver_needs[ver_id])
                else:
                    raise KeyError(f"No ver need: {ver_id}")

        binary = Path("ex")
        with cd(ex_dir / "ex_copy_relo"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # The proxy symbol should have an elfSymbolVersion entry
            sym_environ = next(m.symbols_named("__environ"))
            lib, version = lookup_sym_ver_need(sym_environ)

            self.assertRegex(lib, r"libc\.so\.\d+")
            self.assertRegex(version, r"GLIBC_[\d\.]+")

            sym_environ_copy = next(m.symbols_named("__environ_copy"))
            with self.assertRaises(KeyError, msg=str(sym_environ_copy)):
                lookup_sym_ver_need(sym_environ_copy)

            # Both the copy symbol and proxy symbol should have elfSymbolInfo
            elf_symbol_info = m.aux_data["elfSymbolInfo"].data

            self.assertEqual(
                elf_symbol_info[sym_environ][1:4],
                ("OBJECT", "GLOBAL", "DEFAULT"),
            )
            self.assertEqual(
                elf_symbol_info[sym_environ_copy][1:4],
                ("OBJECT", "GLOBAL", "DEFAULT"),
            )


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
            ir = disassemble(Path("ex.exe")).ir()

            # Check overlay aux data.
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
            ir = disassemble(Path("ex")).ir()

            # Check overlay aux data.
            module = ir.modules[0]
            overlay = module.aux_data["overlay"].data
            self.assertEqual(bytes(overlay), b"OVERLAY")


class OutputTests(unittest.TestCase):
    def test_output_no_dir(self):
        """
        Writing output to a non-existent directory fails
        """
        output_types = (
            ("--ir", "out.gtirb"),
            ("--json", "out.json"),
            ("--asm", "out.s"),
        )

        ext = ".exe" if platform.system() == "Windows" else ""

        with cd(ex_dir / "ex1"):
            proc = subprocess.run(make("clean"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            proc = subprocess.run(make("all"), stdout=subprocess.DEVNULL)
            self.assertEqual(proc.returncode, 0)

            for opt, filename in output_types:
                with self.subTest(opt=opt, filename=filename):
                    args = [
                        "ddisasm",
                        "ex" + ext,
                        opt,
                        os.path.join("nodir", filename),
                    ]
                    proc = subprocess.run(args, capture_output=True)

                    self.assertEqual(proc.returncode, 1)
                    self.assertIn(b"Error: failed to open file", proc.stderr)


class NpadTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows"
        and os.environ.get("VSCMD_ARG_TGT_ARCH") == "x86",
        "This test is Windows (x86) only.",
    )
    def test_npad_data_in_code(self):
        with cd(ex_asm_dir / "ex_npad"):
            subprocess.run(make("clean"), stdout=subprocess.DEVNULL)

            # Build assembly test case for all legacy npad macros.
            subprocess.run(make("all"), stdout=subprocess.DEVNULL)

            # Disassemble to GTIRB file.
            binary = Path("ex.exe")
            result = disassemble(binary)

            # Reassemble test case.
            binary_print(result.ir_path, binary)

            # Check reassembled outputs.
            self.assertTrue(test())

            # Load the GTIRB file and check padding.
            ir = result.ir()
            module = ir.modules[0]
            table = module.aux_data["padding"].data
            padding = sorted(
                (k.element_id.address + k.displacement, v)
                for k, v in table.items()
            )
            sizes = [n for _, n in padding]
            self.assertEqual(sizes, list(range(1, 16)))


class IncrementalLinkingTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_incremental_linking_boundaries(self):
        with cd(ex_dir / "ex1"):
            self.assertTrue(
                compile("cl", "cl", "/O0", ["/link", "/incremental"], [])
            )
            ir = disassemble(
                Path("ex.exe"),
                extra_args=["--with-souffle-relations"],
            ).ir()
            module = ir.modules[0]

            # Read first and last address in incremental linking code.
            first, last = next(
                parse_souffle_output(module, "incremental_linking")
            )

            # locate the .text section byte interval.
            section = next(s for s in module.sections if s.name == ".text")
            bi = next(section.byte_intervals_at(section.address))

            # Pattern match INT3 + JMP sequence prepended to .text section.
            match = re.match(b"^\xCC+(\xe9....)+", bi.contents, re.DOTALL)
            self.assertTrue(match)

            # Test boundaries of the inferred span against matched code.
            code = bi.contents[match.start() : match.end()].lstrip(b"\xCC")
            offset = match.end() - len(code)
            self.assertEqual(section.address + offset, first)
            self.assertEqual(last - first + 5, len(code))


class MalformedPEBinaries(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Windows", "This test is Windows only."
    )
    def test_repeated_import(self):
        """
        Test a binary with repeated import entries
        """
        with cd(ex_dir / "ex1"):
            self.assertTrue(compile("cl", "cl", "/O0", ["/link"], []))

            # We add a duplicate import entry
            bin = lief.PE.parse("ex.exe")
            lib = bin.add_library("KERNEL32.dll")
            lib.add_entry("WriteConsoleW")
            builder = lief.PE.Builder(bin)
            builder.build_imports(True).patch_imports(True)
            builder.build()
            builder.write("ex_mod.exe")

            ir = disassemble(Path("ex_mod.exe")).ir()

            # No duplicate import symbols
            module = ir.modules[0]
            self.assertEqual(
                len(list(module.symbols_named("WriteConsoleW"))), 1
            )
            # LIEF does non-standard things with the IAT.
            # This makes reassembling into a working binary challenging
            # so we don't check that here.


class ZeroEntryPointTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_zero_entry_point(self):
        """
        Test a shared library that has value 0 as its entry point.
        We should not create an inferred symbol for `_start` for
        entry-point 0 for shared libraries.
        """

        library = Path("ex.so")
        with cd(ex_asm_dir / "ex_ifunc"):
            self.assertTrue(compile("gcc", "g++", "-O0 --entry 0", []))
            ir_library = disassemble(library).ir()
            m = ir_library.modules[0]

            # `_start` should not exist in the module.
            self.assertEqual(len(list(m.symbols_named("_start"))), 0)


class TLSLocalExecTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_tls_local_exec(self):
        """
        Test that TLS attributes are correctly generated.
        """

        binary = Path("ex")
        with cd(ex_asm_dir / "ex_tls_local_exec"):
            self.assertTrue(compile("gcc", "g++", "-Os", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            for sym_name in ["var_tpoff_1", "var_tpoff_2"]:
                sym = next(m.symbols_named(sym_name))
                self.assertIsInstance(sym.referent, gtirb.CodeBlock)

                block = sym.referent
                bi = block.byte_interval
                # Get the sym-expr for the first instruction of size 7:
                # movq var@tpoff, %rax
                sexpr = set(
                    bi.symbolic_expressions_at(
                        range(block.address, block.address + 7)
                    )
                )
                self.assertEqual(len(sexpr), 1)
                se = next(iter(sexpr))[2]
                self.assertIsInstance(se, gtirb.SymAddrConst)
                self.assertEqual(se.symbol.name, "var")
                self.assertEqual(se.offset, 0)
                self.assertEqual(
                    se.attributes, {SymbolicExpression.Attribute.TPOFF}
                )


if __name__ == "__main__":
    unittest.main()
