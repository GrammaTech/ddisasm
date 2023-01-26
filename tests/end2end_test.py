import os
import sys
import platform
import tempfile
import unittest
import subprocess
from pathlib import Path

import yaml

from disassemble_reassemble_check import (
    disassemble_reassemble_test as drt,
    skip_reassemble,
)


def compatible_test(config, test):
    # Check the test case is compatible with this platform.
    if "platform" in config:
        if platform.system() not in config["platform"]:
            return False

    # Check if the test case should run in the nightly tests.
    if "nightly" in config:
        if os.environ.get("DDISASM_NIGHTLY"):
            if not config["nightly"]:
                return False

    # Check the test case is compatible with this platform.
    if "platform" in test:
        if platform.system() not in test["platform"]:
            return False

    if "platform" in config and "arch" in test:
        if "Windows" in config["platform"]:
            if os.environ["VSCMD_ARG_TGT_ARCH"] != test["arch"]:
                return False
    return True


class TestExamples(unittest.TestCase):
    def setUp(self):
        self.configs = Path("./tests/").glob("*.yaml")
        if __name__ == "__main__" and sys.argv[1:]:
            self.configs = [
                arg for arg in sys.argv[1:] if arg.endswith(".yaml")
            ]

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_1(self):
        self.assertTrue(
            drt(
                "examples/ex1",
                "ex",
                skip_test=True,
                reassemble_function=skip_reassemble,
                optimizations=[],
            )
        )

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
            # the relative path to the datalog requires "../../"
            ddisasm_opts = [
                "--interpreter",
                "../../src/datalog/main.dl",
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

    def test_examples(self):
        for path in self.configs:
            # Parse YAML config file.
            with open(str(path)) as f:
                config = yaml.safe_load(f)
            platform_compatible = compatible_test(config, {})
            # Run setup command.
            if platform_compatible and "setup" in config:
                subprocess.run(config["setup"])
            # Run all test cases for this host.
            for test in config["tests"]:
                with self.subTest(test=test):
                    if not compatible_test(config, test):
                        self.skipTest("skipping incompatible test")
                    self.disassemble_example(test)
            # Run teardown command.
            if platform_compatible and "teardown" in config:
                subprocess.run(config["teardown"])

    def disassemble_example(self, config):
        path = Path(config["path"]) / config["name"]
        binary = config.get("binary", config["name"])
        args = {
            "extra_compile_flags": config["build"]["flags"],
            "extra_reassemble_flags": config["reassemble"]["flags"],
            "extra_link_flags": config.get("link", {}).get("flags", []),
            "linker": config.get("link", {}).get("linker"),
            "reassembly_compiler": config["reassemble"]["compiler"],
            "c_compilers": config["build"]["c"],
            "cxx_compilers": config["build"]["cpp"],
            "optimizations": config["build"]["optimizations"],
            "strip_exe": config["test"].get("strip_exe", "strip-dummy"),
            "strip": config["test"].get("strip", False),
            "sstrip": config["test"].get("sstrip", False),
            "skip_test": config["test"].get("skip", False),
            "check_cfg": config["test"].get("check_cfg", False),
            "exec_wrapper": config["test"].get("wrapper"),
            "arch": config.get("arch"),
            "extra_ddisasm_flags": config.get("disassemble", {}).get(
                "flags", []
            ),
        }
        if config["reassemble"].get("skip", False):
            args["reassemble_function"] = skip_reassemble
        self.assertTrue(drt(path, binary, **args))


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
