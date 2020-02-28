import platform
import unittest
import subprocess
from disassemble_reassemble_check import compile, cd, disassemble, test
from pathlib import Path
import gtirb


ex_dir = Path("./examples/")


class MultModuleTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux", "This test is linux only.")
    def test_multiple_modules(self):
        """
        Test that we can disassemble and reassemble a
        binary with two modules.
        """
        binary = "ex"
        library = "fun.so"
        with cd(ex_dir / "ex_dyn_library"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            self.assertTrue(
                disassemble(binary, False, format="--ir", extension="gtirb",)
            )
            self.assertTrue(
                disassemble(library, False, format="--ir", extension="gtirb",)
            )
            ir_binary = gtirb.IR.load_protobuf(binary + ".gtirb")
            ir_library = gtirb.IR.load_protobuf(library + ".gtirb")
            ir_binary.modules.append(ir_library.modules[0])
            ir_binary.save_protobuf("two_modules.gtirb")
            completedProcess = subprocess.run(
                ["gtirb-binary-printer", "--ir", "two_modules.gtirb", "-b", binary]
            )
            assert completedProcess.returncode == 0
            assert test()
