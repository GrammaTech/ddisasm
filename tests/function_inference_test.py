import unittest
from disassemble_reassemble_check import compile,disassemble,cd
import gtirb
import os
from pathlib import Path

ex_dir=Path('./examples/')


def get_function_addresses(module):
    addresses=set()
    for k,entrySet in module.aux_data.get('functionEntries').data.items():
        for block in entrySet:
            addresses.add(block.address)
    return addresses


class TestFunctionInference(unittest.TestCase):

    def check_function_inference(self,make_dir,binary,c_compiler,cxx_compiler,optimization):
        """ Test that the function inference finds all the functions"""
        with cd(ex_dir/make_dir):
            self.assertTrue(compile(c_compiler,cxx_compiler,optimization,[]))
            self.assertTrue(disassemble(binary,False,format='--ir',extension='gtirb',extra_args=['--skip-function-analysis']))
            module=gtirb.IR.load_protobuf(binary+'.gtirb').modules[0]
            self.assertTrue(disassemble(binary,True,format='--ir',extension='gtirb'))
            moduleStripped=gtirb.IR.load_protobuf(binary+'.gtirb').modules[0]
            self.assertEqual(get_function_addresses(module),get_function_addresses(moduleStripped))

    def test_functions_ex1(self):
        self.check_function_inference('ex1','ex','gcc','g++','-O0')


if __name__ == '__main__':
    unittest.main()
