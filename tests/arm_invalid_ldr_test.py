import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb

ex_arm_asm_dir = Path("./examples/arm_asm_examples")


class ArmInvalidLdrTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_invalid_ldr(self):
        """
        Test ARM32 invalid load instructions are not disassembled as code.
        """
        binary = "ex"
        adder_dir = ex_arm_asm_dir / "ex_ldr"
        with cd(adder_dir):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )

            # collect the invalid symbols
            self.assertTrue(disassemble(binary, format="--ir",))
            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]
            invalid_syms = [
                sym.name
                for sym in m.symbols
                if sym.name.startswith(".INVALID")
            ]
            extra_strip_flags = ["--keep-symbol=main"]
            for sym in invalid_syms:
                extra_strip_flags.append("--keep-symbol={}".format(sym))

            self.assertTrue(
                disassemble(
                    binary,
                    strip_exe="arm-linux-gnueabihf-strip",
                    strip=True,
                    format="--ir",
                    extra_strip_flags=extra_strip_flags,
                )
            )

            ir_library = gtirb.IR.load_protobuf(binary + ".gtirb")
            m = ir_library.modules[0]

            main_first_block = None
            blocks_are_data = []
            for sym in m.symbols:
                if sym.name == "main":
                    main_first_block = sym.referent
                    continue
                if not sym.name.startswith(".INVALID"):
                    continue

                blocks_are_data.append(
                    isinstance(sym.referent, gtirb.DataBlock)
                )

            self.assertTrue(isinstance(main_first_block, gtirb.CodeBlock))
            self.assertTrue(all(blocks_are_data))
            self.assertEqual(len(blocks_are_data), len(invalid_syms))


if __name__ == "__main__":
    unittest.main()
