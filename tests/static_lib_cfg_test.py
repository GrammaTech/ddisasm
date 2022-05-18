import platform
import unittest
from pathlib import Path

import gtirb
import yaml

from disassemble_reassemble_check import compile, disassemble, cd

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

                binary = "libtest.a"

                gtirb_file = "libtest.gtirb"
                self.assertTrue(
                    disassemble(binary, gtirb_file, format="--ir")[0]
                )

                ir_library = gtirb.IR.load_protobuf(gtirb_file)
                blocks = None
                for m in ir_library.modules:
                    if "foo_" in m.name:
                        blocks = m.code_blocks

                self.assertIsNotNone(blocks)

                block = None
                for b in blocks:
                    edge_types = {e.label.type for e in b.outgoing_edges}
                    if edge_types == {gtirb.Edge.Type.Branch}:
                        block = b

                self.assertIsNotNone(block)
