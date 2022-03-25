import platform
import sys
import unittest
from pathlib import Path

import gtirb
import yaml

from check_gtirb import lookup_sym
from disassemble_reassemble_check import compile, disassemble, cd

ex_dir = Path("./examples/")


class TestStackChkFallthrough(unittest.TestCase):
    def configs(self):
        test_dir = Path("./tests/")
        self.configs = [
            test_dir / "linux-elf-x86.yaml",
            test_dir / "linux-elf-x64.yaml",
            test_dir / "qemu-elf-arm.yaml",
            test_dir / "qemu-elf-arm64.yaml",
            # TODO: mips doesn't seem to be generating the CFG correctly for
            # the PLT block at all.
            # test_dir / 'qemu-elf-mips32.yaml',
        ]

        for path in self.configs:
            # Parse YAML config file.
            with open(path) as f:
                config = yaml.safe_load(f)

            default = config.get("default")
            flags = default.get("build").get("flags")
            flags.append("-fstack-protector-all")

            yield {
                "platform": path.stem,
                "args": (
                    default.get("build").get("c")[0],
                    default.get("build").get("cpp")[0],
                    default.get("build").get("optimizations")[0],
                    flags,
                    default.get("test").get("wrapper"),
                ),
            }

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_chk_fallthrough(self):
        for config in self.configs():
            with cd(ex_dir / "ex1"), self.subTest(platform=config["platform"]):
                self.assertTrue(compile(*config["args"]))

                binary = "ex"
                gtirb_path = binary + ".gtirb"
                self.assertTrue(
                    disassemble(binary, gtirb_path, format="--ir")[0]
                )

                ex_ir = gtirb.IR.load_protobuf(gtirb_path)
                module = ex_ir.modules[0]

                # Locate the PLT block for __stack_chk_fail
                for node in module.cfg_nodes:
                    if (
                        isinstance(node, gtirb.ProxyBlock)
                        and lookup_sym(node) == "__stack_chk_fail"
                    ):
                        proxy = node
                        break
                else:
                    self.fail("Did not find __stack_chk_fail PLT entry")

                # The ProxyBlock should have one incoming branch edge from
                # the PLT.
                self.assertEqual(len(list(proxy.incoming_edges)), 1)
                plt_edge = next(proxy.incoming_edges)
                self.assertEqual(plt_edge.label.type, gtirb.Edge.Type.Branch)
                plt = plt_edge.source

                # Ensure that calls to the PLT entry have no fallthrough.
                for call_edge in plt.incoming_edges:
                    # All edges to the stack_chk_fail ProxyBlock should be
                    # calls
                    self.assertEqual(
                        call_edge.label.type, gtirb.Edge.Type.Call
                    )

                    # The calling block should not have a fallthrough.
                    self.assertTrue(
                        all(
                            e.label.type != gtirb.Edge.Type.Fallthrough
                            for e in call_edge.source.outgoing_edges
                        )
                    )


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
