from collections import defaultdict
import ctypes
import platform
import subprocess
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb
from typing import Dict, Set


ex_asm_arm_dir = Path("./examples/") / "arm_asm_examples"
ex_asm_x64_dir = Path("./examples/") / "asm_examples"
ex_asm_x86_dir = Path("./examples/") / "x86_32_asm_examples"


class ValueRegTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_value_reg_arm32(self):
        """
        Test that value_reg computes correct values.
        """
        binary = Path("ex")
        with cd(ex_asm_arm_dir / "ex_value_reg"):
            self.assertTrue(
                compile(
                    "arm-linux-gnueabihf-gcc",
                    "arm-linux-gnueabihf-g++",
                    "-O0",
                    [],
                    "qemu-arm -L /usr/arm-linux-gnueabihf",
                )
            )
            ir_library = disassemble(
                binary,
                strip=False,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]

            fun = [s for s in m.symbols if s.name == "fun"][0]
            fun_block = fun.referent

            points = [
                edge.source.address + edge.source.size - 16
                for edge in fun_block.incoming_edges
                if edge.label.type == gtirb.Edge.Type.Call
            ]
            points.sort()

            result = subprocess.run(
                ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", binary],
                stdout=subprocess.PIPE,
            )
            values = list(map(int, result.stdout.decode("utf-8").split()))

            assert len(values) == len(points)

            points_to_values = dict(zip(points, values))

            value_regs = (
                m.aux_data["souffleOutputs"]
                .data["disassembly.value_reg"][1]
                .strip()
                .split("\n")
            )

            souffle_outputs = {}
            for tupl in value_regs:
                tupl = tupl.split("\t")

                ea0 = int(tupl[0], 0)
                ea = ea0 - (ea0 & 1)
                val = int(tupl[5], 0)
                souffle_outputs[ea] = val

            for ea in points_to_values:
                if ea in souffle_outputs:
                    val0 = souffle_outputs[ea]
                    baseline = ctypes.c_int32(points_to_values[ea]).value
                    val = ctypes.c_int32(val0).value
                    if val != baseline:
                        self.fail(f"{ea:#x}: {val} != {baseline}")
                else:
                    self.fail(f"{ea:#x}: no value_reg found")

    def parse_best_value_reg(
        self, m: gtirb.Module
    ) -> Dict[int, Dict[str, Set[int]]]:
        """
        Parse complete values of the best_value_reg disassembly
        table into a nested dictionary indexed by address and register.
        """
        table = (
            m.aux_data["souffleOutputs"]
            .data["disassembly.best_value_reg"][1]
            .strip()
            .split("\n")
        )

        value_reg = defaultdict(lambda: defaultdict(set))
        for tupl in table:
            tupl = tupl.split("\t")
            if tupl[5] != "complete":
                continue
            ea = int(tupl[0], 0)
            reg = tupl[1]
            val = int(tupl[4], 0)
            value_reg[ea][reg].add(val)
        return value_reg

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_value_reg_through_stack_x64(self):
        """
        Test that best_value_reg computes correct values passing values through
        the stack in x64.
        """
        binary = Path("ex")
        with cd(ex_asm_x64_dir / "ex_stack_value_reg"):
            self.assertTrue(compile("gcc", "g++", "", []))
            ir_library = disassemble(
                binary,
                strip=False,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]
            value_reg = self.parse_best_value_reg(m)
            expected = [
                ("pop_4", "RSI", {4}),
                ("pop_2", "RAX", {2}),
                ("read_4", "RSI", {4}),
                ("read_2", "RSI", {2}),
                ("read_3", "RSI", {3}),
                ("read_1", "RSI", {1}),
            ]
            for sym_name, reg, val in expected:
                addr = [
                    sym.referent.address for sym in m.symbols_named(sym_name)
                ][0]
                self.assertEqual(
                    value_reg[addr][reg],
                    val,
                    f"register {reg} at label {sym_name} has"
                    f" values {value_reg[addr][reg]}, expected {val}",
                )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_value_reg_through_stack_x86(self):
        """
        Test that best_value_reg computes correct values passing values through
        the stack in x86.
        """
        binary = Path("ex")
        with cd(ex_asm_x86_dir / "ex_stack_value_reg"):
            self.assertTrue(compile("gcc", "g++", "", ["-m32"]))
            ir_library = disassemble(
                binary,
                strip=False,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]
            value_reg = self.parse_best_value_reg(m)
            expected = [
                ("pop_4", "ESI", {4}),
                ("pop_2", "EAX", {2}),
                ("read_4", "ESI", {4}),
                ("read_2", "ESI", {2}),
                ("read_3", "ESI", {3}),
                ("read_1", "ESI", {1}),
            ]
            for sym_name, reg, val in expected:
                addr = [
                    sym.referent.address for sym in m.symbols_named(sym_name)
                ][0]
                self.assertEqual(
                    value_reg[addr][reg],
                    val,
                    f"register {reg} at label {sym_name} has"
                    f" values {value_reg[addr][reg]}, expected {val}",
                )


if __name__ == "__main__":
    unittest.main()
