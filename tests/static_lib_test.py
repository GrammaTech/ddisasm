import os
import platform
import unittest
from pathlib import Path
import subprocess

import gtirb
import yaml

from disassemble_reassemble_check import compile, disassemble, cd, test, link

ex_dir = Path("./examples/")


class TestStaticLib(unittest.TestCase):
    def setUp(self):
        test_dir = Path("./tests/")
        # TODO: the arm64 architectures, disabled below, has issues with
        # object file support that cause this test to fail, as ddisasm can't
        # properly disassemble and rebuild it.
        self.configs = [
            test_dir / "linux-elf-x86.yaml",
            test_dir / "linux-elf-x64.yaml",
            # test_dir / 'qemu-elf-arm64.yaml',
        ]

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_static_lib(self):
        for path in self.configs:
            # Parse YAML config file.
            with open(path) as f:
                config = yaml.safe_load(f)

            default = config.get("default")
            wrapper = default.get("test").get("wrapper")

            test_dir = ex_dir / "ex_static_lib"
            with cd(test_dir), self.subTest(platform=path.stem):
                self.assertTrue(
                    compile(
                        default.get("build").get("c")[0],
                        default.get("build").get("cpp")[0],
                        default.get("build").get("optimizations")[0],
                        default.get("build").get("flags"),
                        exec_wrapper=wrapper,
                    )
                )

                binary = "libmsg.a"
                modules = [
                    "msg_one",
                    "msg_two",
                    "msg_three",
                    "msg_four_with_a_long_name",
                ]

                gtirb_file = "libmsg.gtirb"
                self.assertTrue(
                    disassemble(binary, gtirb_file, format="--ir")[0]
                )
                self.assertEqual(
                    len(modules),
                    len(gtirb.IR.load_protobuf(gtirb_file).modules),
                )

                asm_dir = Path("libmsg-tmp")
                self.assertTrue(
                    disassemble(binary, str(asm_dir), format="--asm")[0]
                )

                self.assertTrue(asm_dir.exists())
                self.assertTrue(asm_dir.is_dir())

                self.assertEqual(
                    {name + ".s" for name in modules}, set(os.listdir(asm_dir))
                )

                # reassemble object files
                print("# Reassembling", binary + ".s", "into", binary)
                re_compiler = default.get("reassemble").get("compiler")
                re_flags = default.get("reassemble").get("flags")

                for obj in modules:
                    subprocess.run(
                        [
                            re_compiler,
                            "-c",
                            str(asm_dir / (obj + ".s")),
                            "-o",
                            obj + ".o",
                        ]
                        + re_flags,
                        check=True,
                    )

                # re-build static archive
                objects = [obj + ".o" for obj in modules]
                for obj in modules:
                    subprocess.run(
                        ["ar", "-rcs", binary] + objects, check=True
                    )

                # re-link
                objects.append("ex.o")
                self.assertTrue(link(re_compiler, "ex", objects, re_flags))
                self.assertTrue(test(wrapper))
