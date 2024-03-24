import platform
import unittest
from pathlib import Path

import gtirb
import yaml

from disassemble_reassemble_check import (
    compile,
    disassemble,
    cd,
    binary_print,
    test,
)

ex_dir = Path("./examples/")


class TestStaticLibCfg(unittest.TestCase):
    def setUp(self):
        test_dir = Path("./tests/")
        # TODO: mips32, disabled below, has
        # issues with object file support that cause this test to fail, as
        # ddisasm can't properly disassemble.
        self.configs = [
            # test_dir / "linux-elf-x86.yaml",
            test_dir / "linux-elf-x64.yaml",
            test_dir / "qemu-elf-arm.yaml",
            test_dir / "qemu-elf-arm64.yaml",
            # test_dir / "qemu-elf-mips32.yaml",
        ]

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_static_lib_cfg(self):
        for path in self.configs:
            # Parse YAML config file.
            with open(path) as f:
                config = yaml.safe_load(f)

            default = config.get("default")
            wrapper = default.get("test").get("wrapper")
            flags = default.get("build").get("flags")

            test_dir = ex_dir / "ex_static_lib_cfg"

            with cd(test_dir), self.subTest(platform=path.stem, flags=flags):
                self.assertTrue(
                    compile(
                        default.get("build").get("c")[0],
                        default.get("build").get("cpp")[0],
                        default.get("build").get("optimizations")[0],
                        flags,
                        exec_wrapper=wrapper,
                    )
                )

                binary = Path("libtest.a")
                ir_library = disassemble(binary).ir()
                module = None
                for m in ir_library.modules:
                    if "foo_" in m.name:
                        module = m

                self.assertIsNotNone(module)

                sym = next(module.symbols_named("jmp_block"))
                block = sym.referent
                self.assertEqual(
                    {e.label.type for e in block.outgoing_edges},
                    {gtirb.Edge.Type.Branch},
                )
                self.assertEqual(len(list(block.outgoing_edges)), 1)
                last_sym_expr = None
                for _, _, sym_expr in m.symbolic_expressions_at(
                    range(block.address, block.address + block.size)
                ):
                    last_sym_expr = sym_expr
                self.assertIsNotNone(last_sym_expr)
                self.assertEqual(next(last_sym_expr.symbols).name, "bar")


class TestStaticLibCfgArm64Object(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_static_lib_cfg_bar_object(self):
        """
        Test null-transform of bar.o from ex_static_lib_cfg on ARM64
        """
        binary = Path("bar.o")

        with cd("examples/ex_static_lib_cfg"):

            for opt in ["-O0", "-O1", "-O2", "-O3", "-Os"]:
                with self.subTest(optimization=opt):
                    compiler = "aarch64-linux-gnu-gcc"
                    wrapper = "qemu-aarch64 -L /usr/aarch64-linux-gnu"
                    self.assertTrue(
                        compile(
                            compiler,
                            "",
                            opt,
                            [],
                            exec_wrapper=wrapper,
                        )
                    )

                    result = disassemble(binary)

                    # Rebuilds bar.o with gtirb-pprinter --object --binary...
                    # The `check` target depends on `bar.o` (transitively),
                    # so everything is rebuilt with the rewritten `bar.o`
                    # when we run `check`.
                    binary_print(
                        result.ir_path,
                        binary,
                        compiler=compiler,
                        build_object=True,
                    )
                    self.assertTrue(test(compiler, wrapper))
