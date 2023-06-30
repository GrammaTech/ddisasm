import os
import platform
import subprocess
import tempfile
import unittest
from disassemble_reassemble_check import (
    compile,
    cd,
    disassemble,
    disassemble_reassemble_test as drt,
)
from pathlib import Path
import gtirb


ex_dir = Path("./examples/")
ex_asm_dir = ex_dir / "asm_examples"


class ExtraArgsTest(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_user_hints(self):
        """Test `--hints'. The test disassembles, checks
        the address of main and disassembles again with
        a hint that makes main invalid. After the second
        disassembly, main is not considered code.
        """

        with cd(ex_dir / "ex1"):
            # build
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # disassemble
            self.assertTrue(disassemble("ex", format="--ir")[0])

            # load the gtirb
            ir = gtirb.IR.load_protobuf("ex.gtirb")
            m = ir.modules[0]

            main_sym = next(sym for sym in m.symbols if sym.name == "main")
            main_block = main_sym.referent
            self.assertIsInstance(main_block, gtirb.CodeBlock)
            # dissasemble with hints
            with tempfile.TemporaryDirectory() as debug_dir:
                with tempfile.NamedTemporaryFile(mode="w") as hints_file:
                    # we add a couple of incorrect hints to test error checking
                    print(
                        "disassembly.not-a-real-predicate\t10", file=hints_file
                    )
                    print(
                        "disassembly.invalid\tnot-address\tbad-hint",
                        file=hints_file,
                    )
                    print("disassembly.invalid\t0x100000", file=hints_file)

                    # good hint with extra fields
                    print(
                        "disassembly.invalid\t0x0\tuser-provided-extra-field"
                        "\tthe-extra-field",
                        file=hints_file,
                        flush=True,
                    )
                    # we add the good hint at the end
                    print(
                        "disassembly.invalid\t{}\tuser-provided-hint".format(
                            main_block.address
                        ),
                        file=hints_file,
                        flush=True,
                    )
                    self.assertTrue(
                        disassemble(
                            "ex",
                            format="--ir",
                            extra_args=[
                                "--debug-dir",
                                debug_dir,
                                "--hints",
                                hints_file.name,
                            ],
                        )[0]
                    )

                # load the new gtirb
                ir = gtirb.IR.load_protobuf("ex.gtirb")
                m = ir.modules[0]

                main_sym = next(sym for sym in m.symbols if sym.name == "main")
                # main cannot be code if we tell it explicitly that
                # it contains an invalid instruction through hints
                main_block = main_sym.referent
                self.assertIsInstance(main_block, gtirb.DataBlock)
                invalid_text = (
                    Path(debug_dir) / "disassembly" / "invalid.csv"
                ).read_text()
                self.assertIn("user-provided-hint", invalid_text)
                # the entry with extra fields is taken but the
                # extra field is ignored
                self.assertIn("user-provided-extra-field", invalid_text)
                self.assertNotIn("the-extra-field", invalid_text)
                # the incorrect hints are not included
                self.assertNotIn("bad-hint", invalid_text)
                self.assertNotIn("0x100000", invalid_text)

    @unittest.skipUnless(
        os.path.exists("./build/lib/libfunctors.so")
        and platform.system() == "Linux",
        "This test is linux only.",
    )
    def test_interpreter(self):
        """
        Test running the interpreter
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # ddisasm executes with examples/ex1 as the working directory, so
            # the relative path to the repository root is "../../"
            ddisasm_opts = [
                "--interpreter",
                "../../",
                "--debug-dir",
                tmpdir,
            ]
            self.assertTrue(
                drt(
                    "examples/ex1",
                    "ex",
                    optimizations=["-O0"],
                    extra_compile_flags=["-pie"],
                    extra_ddisasm_flags=ddisasm_opts,
                    extra_reassemble_flags=["-nostartfiles", "-pie"],
                    upload=False,
                )
            )

    def test_builtin_profiling(self):
        """
        Test ddisasm compiled with DDISASM_SOUFFLE_PROFILING
        """
        p = subprocess.run(["ddisasm", "--version"], capture_output=True)
        if "profiling enabled" not in p.stdout.decode():
            self.skipTest("Profiling not enabled")

        with tempfile.TemporaryDirectory() as tmpdir, cd(ex_dir / "ex1"):
            profile_dir_path = Path(tmpdir, "profiles")

            # build
            self.assertTrue(compile("gcc", "g++", "-O0", []))

            # disassemble
            self.assertTrue(
                disassemble(
                    "ex",
                    format="--ir",
                    extra_args=["--profile", profile_dir_path],
                )[0]
            )

            profiles = [
                profile_dir_path / filename
                for filename in (
                    "disassembly.prof",
                    # TODO: profile information from the other passes is broken
                    # "function-inference.prof",
                    # "no-return-analysis.prof",
                )
            ]

            for profile_path in profiles:
                self.assertTrue(profile_path.exists())
                print(profile_path)
                p = subprocess.run(
                    ["souffleprof", "-c", "top", profile_path],
                    capture_output=True,
                )

                # Verify souffleprof includes some reasonable output
                self.assertIn(
                    "Slowest relations to fully evaluate", p.stdout.decode()
                )


if __name__ == "__main__":
    unittest.main()
