import os
import string
import difflib
import unittest
import subprocess
from pathlib import Path

import platform

from disassemble_reassemble_check import cd, disassemble
from rename_externs import rename_externs

tests_path = Path(os.path.dirname(os.path.realpath(__file__)))
examples_path = tests_path.parent / "examples"

DISABLED = True

def compile(*args):
    proc = subprocess.run([
        "cl32",
        "/nologo",
        *args
        ], stdout=subprocess.DEVNULL)
    return proc.returncode == 0

def rename_symbols(path):
    with open(path, "r+") as asm:
        with open(tests_path / "kernel32.lib") as lib:
            rename_externs(asm, [lib])

def reassemble(*args):
    proc = subprocess.run([
        "ml", "/nologo",
        *args,
        "/Fe", "out.exe",
        "/link", "/subsystem:console", "/entry:__EntryPoint"
    ], stdout=subprocess.DEVNULL)
    return proc.returncode == 0

def diff_output(args1, args2):
    args1.insert(0, "wine")
    args2.insert(0, "wine")
    original_output = subprocess.check_output(args1)
    reassembled_output = subprocess.check_output(args2)
    if original_output != reassembled_output:
        diff = difflib.unified_diff(original_output, reassembled_output)
        print(diff)
        return False
    return True

def cleanup():
    subprocess.check_call(["git", "clean", "-fx", "."])

class TestPE32(unittest.TestCase):

    def bdrt(self, name, *sources):
        """Build,Disassemble,Reassemble,Test"""

        def inner(*flags):
            with cd(examples_path / name):
                self.assertTrue(compile(*flags, *sources))
                self.assertTrue(disassemble("ex.exe", False, extension="asm", extra_args=["-F"]))
                rename_symbols("ex.exe.asm")
                self.assertTrue(reassemble("ex.exe.asm"))
                self.assertTrue(diff_output(["ex.exe"], ["out.exe"]))
                cleanup()

        for flag in ["/Od", "/Ot", "/O1", "/Ox", "/O2"]:
            inner(flag)

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex1(self):
        self.bdrt("ex1", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_2modulesPIC(self):
        self.bdrt("ex_2modulesPIC", "ex.c", "fun.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_confusing_data(self):
        self.bdrt("ex_confusing_data", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_false_pointer_array(self):
        self.bdrt("ex_false_pointer_array", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_float(self):
        self.bdrt("ex_float", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_noreturn(self):
        self.bdrt("ex_noreturn", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_pointerReatribution(self):
        self.bdrt("ex_pointerReatribution", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_pointerReatribution2(self):
        self.bdrt("ex_pointerReatribution2", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_pointerReatribution3(self):
        self.bdrt("ex_pointerReatribution3", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_struct(self):
        self.bdrt("ex_struct", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_switch(self):
        self.bdrt("ex_switch", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_uninitialized_data(self):
        self.bdrt("ex_uninitialized_data", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_legacy_switch_001(self):
        def inner(*flags):
            with cd(examples_path / "ex_legacy_switch.001"):
                self.assertTrue(compile(*flags, "main.c"))
                self.assertTrue(disassemble("main.exe", False, extension="asm", extra_args=["-F"]))
                rename_symbols("main.exe.asm")
                self.assertTrue(reassemble("main.exe.asm"))
                for char in string.ascii_uppercase:
                    self.assertTrue(diff_output(["main.exe", char], ["out.exe", char]))
                cleanup()
        for flag in ["/Od", "/Ot", "/O1", "/Ox", "/O2"]:
            inner(flag)

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_legacy_switch_002(self):
        def inner(*flags):
            with cd(examples_path / "ex_legacy_switch.002"):
                self.assertTrue(compile(*flags, "main.c"))
                self.assertTrue(disassemble("main.exe", False, extension="asm", extra_args=["-F"]))
                rename_symbols("main.exe.asm")
                self.assertTrue(reassemble("main.exe.asm"))
                for char in string.ascii_uppercase:
                    self.assertTrue(diff_output(["main.exe", char], ["out.exe", char]))
                cleanup()
        for flag in ["/Od", "/Ot", "/O1", "/Ox", "/O2"]:
            inner(flag)

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_legacy_switch_003(self):
        def inner(*flags):
            with cd(examples_path / "ex_legacy_switch.003"):
                self.assertTrue(compile(*flags, "main.c"))
                self.assertTrue(disassemble("main.exe", False, extension="asm", extra_args=["-F"]))
                rename_symbols("main.exe.asm")
                self.assertTrue(reassemble("main.exe.asm"))
                for arg in [750, 800, 900, 700, 500, 250, 100, 200, 600]:
                    self.assertTrue(diff_output(["main.exe", str(arg)], ["out.exe", str(arg)]))
                cleanup()
        for flag in ["/Od", "/Ot", "/O1", "/Ox", "/O2"]:
            inner(flag)

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_legacy_switch_004(self):
        def inner(*flags):
            with cd(examples_path / "ex_legacy_switch.004"):
                self.assertTrue(compile(*flags, "main.c"))
                self.assertTrue(disassemble("main.exe", False, extension="asm", extra_args=["-F"]))
                rename_symbols("main.exe.asm")
                self.assertTrue(reassemble("main.exe.asm"))
                seq = ['002', '003', '004', '005', '006', '007', '008', '009',
                '010', '011', '012', '013', '014', '015', '016', '017', '018',
                '019', '020', '902', '903', '904', '905', '906', '907', '908',
                '909', '910', '911', '912', '913', '914', '915', '916', '917',
                '918', '919', '920', '602', '603', '604', '605', '606', '607',
                '608', '609', '610', '611', '612', '613', '614', '615', '616',
                '617', '618', '619', '620']
                for arg in seq:
                    self.assertTrue(diff_output(["main.exe", str(arg)], ["out.exe", str(arg)]))
                cleanup()
        for flag in ["/Od", "/Ot", "/O1", "/Ox", "/O2"]:
            inner(flag)

    # TODO: Fatal error compiling CPP with CL under WINE with the current ENV.
    #       Works manually on binary compiled on Windows.
    # @unittest.skipUnless(not DISABLED, "WIP test cases")
    # def test_ex_member_pointer(self):
    #     self.bdrt("ex_member_pointer", "ex.c")

    @unittest.skipUnless(not DISABLED, "WIP test cases")
    def test_ex_virtualDispatch(self):
        self.bdrt("ex_virtualDispatch", "ex.cpp")

if __name__ == "__main__":
    unittest.main()
