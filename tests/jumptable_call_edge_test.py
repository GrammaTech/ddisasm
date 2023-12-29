import platform
import sys
import unittest
from pathlib import Path

import gtirb
import yaml

from check_gtirb import lookup_sym
from disassemble_reassemble_check import compile, disassemble, cd

ex_dir = Path("./examples/")


class TestJumptableCallEdge(unittest.TestCase):
    def configs(self):
        test_dir = Path("./tests/")
        # Only test x86/x86_64
        # Other arch don't generate jumptables for this code
        self.configs = [
            test_dir / "linux-elf-x86.yaml",
            test_dir / "linux-elf-x64.yaml",
        ]

        for path in self.configs:
            # Parse YAML config file.
            with open(path) as f:
                config = yaml.safe_load(f)

            default = config.get("default")
            yield {
                "platform": path.stem,
                "args": (
                    default.get("build").get("c")[0],
                    default.get("build").get("cpp")[0],
                    default.get("build").get("optimizations")[0],
                    default.get("build").get("flags"),
                    default.get("test").get("wrapper"),
                ),
            }

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_jumptable_call_edge(self):
        for config in self.configs():
            with cd(ex_dir / "ex_call_array"), self.subTest(
                platform=config["platform"]
            ):
                self.assertTrue(compile(*config["args"]))

                binary = Path("ex")
                ex_ir = disassemble(binary).ir()
                module = ex_ir.modules[0]

                # Locate the jumptable where the functions are called
                funcs = {"one", "two", "three", "four"}
                for node in module.cfg_nodes:

                    targets = {
                        lookup_sym(edge.target) for edge in node.outgoing_edges
                    }
                    if funcs.issubset(targets):
                        jumptable = node
                        break

                else:
                    self.fail("Did not find jumptable")

                # The edges to the functions should be calls.
                for edge in jumptable.outgoing_edges:
                    if lookup_sym(edge.target) not in funcs:
                        continue

                    self.assertEqual(edge.label.type, gtirb.Edge.Type.Call)


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
