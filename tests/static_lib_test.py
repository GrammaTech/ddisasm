import enum
import os
import platform
import unittest
from pathlib import Path
import subprocess
from typing import List

import gtirb
import yaml

from disassemble_reassemble_check import compile, disassemble, cd, test, link

ex_dir = Path("./examples/")


class ExecType(enum.Enum):
    PIE = 1
    NO_PIE = 2


def get_flags(base: List[str], mode: ExecType) -> List[str]:
    """
    Modify the arch flags for PIE or non-PIE
    """
    new_flags = []

    flags_pie = ["-fpie", "-pie"]
    flags_no_pie = ["-fno-pie", "-no-pie"]
    flags_all = flags_pie + flags_no_pie

    for flag in base:
        if flag in flags_all:
            continue

        new_flags.append(flag)

    if mode == ExecType.PIE:
        new_flags.extend(flags_pie)

    elif mode == ExecType.NO_PIE:
        new_flags.extend(flags_no_pie)

    return new_flags


class TestStaticLib(unittest.TestCase):
    def setUp(self):
        test_dir = Path("./tests/")
        # TODO: arm64 and mips32 architectures, disabled below, have
        # issues with object file support that cause this test to fail, as
        # ddisasm can't properly disassemble and rebuild it.
        self.configs = [
            test_dir / "linux-elf-x86.yaml",
            test_dir / "linux-elf-x64.yaml",
            test_dir / "qemu-elf-arm.yaml",
            # test_dir / 'qemu-elf-arm64.yaml',
            # test_dir / 'qemu-elf-mips32.yaml',
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
            base_flags = default.get("build").get("flags")

            test_dir = ex_dir / "ex_static_lib"

            for exec_type in ExecType:
                flags = get_flags(base_flags, exec_type)

                if (path.stem, exec_type) in (
                    ("linux-elf-x86", ExecType.PIE),
                    ("qemu-elf-arm", ExecType.NO_PIE),
                ):
                    # TODO: fix and re-enable this.
                    # See issue #330, #331
                    continue

                with cd(test_dir), self.subTest(
                    platform=path.stem, flags=flags
                ):
                    self.assertTrue(
                        compile(
                            default.get("build").get("c")[0],
                            default.get("build").get("cpp")[0],
                            default.get("build").get("optimizations")[0],
                            flags,
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
                        {name + ".s" for name in modules},
                        set(os.listdir(asm_dir)),
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
