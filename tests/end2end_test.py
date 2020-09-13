import platform
import unittest
from pathlib import Path

import yaml
import distro

from disassemble_reassemble_check import (
    disassemble_reassemble_test as drt,
    skip_reassemble,
)

def compatible_test(config, test):
    # Check the test case is compatible with this platform.
    if "platform" in config:
        if platform.system() != config["platform"]:
            return False

    # Check the test case is compatible with this distro.
    if "distro" in config:
        if distro.name() not in config["distro"]["name"]:
            return False
        if distro.version() not in config["distro"]["version"]:
            return False

    return True

class TestExamples(unittest.TestCase):
    def setUp(self):
        self.configs = Path("./tests/").glob("*.yaml")

    def test_examples(self):
        for path in self.configs:
            # Parse YAML config file.
            with open(path) as f:
                config = yaml.safe_load(f)
            # Run all test cases for this host.
            for test in config["tests"]:
                with self.subTest(test=test):
                    if not compatible_test(config, test):
                        self.skipTest("skipping incompatible test")
                    self.disassemble_example(test)

    def disassemble_example(self, config):
        path = Path(config["path"]) / config["name"]
        binary = config.get("binary", config["name"])
        args = {
            "extra_compile_flags": config["build"]["flags"],
            "extra_reassemble_flags": config["reassemble"]["flags"],
            "reassembly_compiler": config["reassemble"]["compiler"],
            "c_compilers": config["build"]["c"],
            "cxx_compilers": config["build"]["cpp"],
            "optimizations": config["build"]["optimizations"],
            "strip": config["test"].get("strip", False),
            "skip_test": config["test"].get("skip", False),
            "exec_wrapper": config["test"].get("wrapper"),
        }
        if config["reassemble"].get("skip", False):
            args["reassemble_function"] = skip_reassemble
        self.assertTrue(drt(path, binary, **args))


if __name__ == '__main__':
    unittest.main()
