import unittest
from disassemble_reassemble_check import compile,disassemble,cd
import gtirb
import os
from pathlib import Path

ex_dir=Path('./examples/')
asm_dir=Path('./examples/asm_examples/')

class TestFunctionInference(unittest.TestCase):

    def get_function_addresses(self,module):
        addresses=set()
        for _,entrySet in module.aux_data.get('functionEntries').data.items():
            for block in entrySet:
                addresses.add(block.address)
        return addresses

    def check_function_inference(self,make_dir,binary,c_compiler,cxx_compiler,optimization):
        """ Test that the function inference finds all the functions
            Compare the functions found with only function symbols and calls in a non-stripped binary
            with the functions found with the advanced analysis in the stripped binary"""
        with cd(make_dir):
            self.assertTrue(compile(c_compiler,cxx_compiler,optimization,[]))
            self.assertTrue(disassemble(binary,False,format='--ir',extension='gtirb',extra_args=['--skip-function-analysis']))
            module=gtirb.IR.load_protobuf(binary+'.gtirb').modules[0]
            self.assertTrue(disassemble(binary,True,format='--ir',extension='gtirb'))
            moduleStripped=gtirb.IR.load_protobuf(binary+'.gtirb').modules[0]
            self.assertEqual(self.get_function_addresses(module),self.get_function_addresses(moduleStripped))

    def test_functions_ex1(self): self.check_function_inference(ex_dir/'ex1','ex','gcc','g++','-O3')
    def test_functions_2modulesPIC(self): self.check_function_inference(ex_dir/'ex_2modulesPIC','ex','gcc','g++','-O3')
    def test_functions_confusing_data(self): self.check_function_inference(ex_dir/'ex1','ex','gcc','g++','-O3')
    def test_functions_exceptions1(self): self.check_function_inference(ex_dir/'ex_exceptions1','ex','gcc','g++','-O3')
    def test_functions_exceptions2(self): self.check_function_inference(ex_dir/'ex_exceptions2','ex','gcc','g++','-O3')
    def test_functions_exceptions3(self): self.check_function_inference(ex_dir/'ex_exceptions3','ex','gcc','g++','-O3')
    def test_functions_false_pointer_array(self): self.check_function_inference(ex_dir/'ex_false_pointer_array','ex','gcc','g++','-O3')
    def test_functions_float(self): self.check_function_inference(ex_dir/'ex_float','ex','gcc','g++','-O3')
    def test_functions_fprintf(self): self.check_function_inference(ex_dir/'ex_fprintf','ex','gcc','g++','-O3')
    def test_functions_getoptlong(self): self.check_function_inference(ex_dir/'ex_getoptlong','ex','gcc','g++','-O3')
    def test_functions_memberPointer(self): self.check_function_inference(ex_dir/'ex_memberPointer','ex','gcc','g++','-O3')
    def test_functions_noreturn(self): self.check_function_inference(ex_dir/'ex_noreturn','ex','gcc','g++','-O3')
    def test_functions_pointerReatribution(self): self.check_function_inference(ex_dir/'ex_pointerReatribution','ex','gcc','g++','-O3')
    def test_functions_pointerReatribution2(self): self.check_function_inference(ex_dir/'ex_pointerReatribution2','ex','gcc','g++','-O3')
    def test_functions_pointerReatribution3(self): self.check_function_inference(ex_dir/'ex_pointerReatribution3','ex','gcc','g++','-O3')
    def test_functions_stat(self): self.check_function_inference(ex_dir/'ex_stat','ex','gcc','g++','-O3')
    def test_functions_struct(self): self.check_function_inference(ex_dir/'ex_struct','ex','gcc','g++','-O3')
    def test_functions_switch(self): self.check_function_inference(ex_dir/'ex_switch','ex','gcc','g++','-O3')
    def test_functions_uninitialized_data(self): self.check_function_inference(ex_dir/'ex_uninitialized_data','ex','gcc','g++','-O3')
    def test_functions_virtualDispatch(self): self.check_function_inference(ex_dir/'ex_virtualDispatch','ex','gcc','g++','-O3')

    def test_functions_ex1_clang(self): self.check_function_inference(ex_dir/'ex1','ex','clang','clang++','-O3')
    def test_functions_2modulesPIC_clang(self): self.check_function_inference(ex_dir/'ex_2modulesPIC','ex','clang','clang++','-O3')
    def test_functions_confusing_data_clang(self): self.check_function_inference(ex_dir/'ex1','ex','clang','clang++','-O3')
    def test_functions_exceptions1_clang(self): self.check_function_inference(ex_dir/'ex_exceptions1','ex','clang','clang++','-O3')
    def test_functions_exceptions2_clang(self): self.check_function_inference(ex_dir/'ex_exceptions2','ex','clang','clang++','-O3')
    def test_functions_exceptions3_clang(self): self.check_function_inference(ex_dir/'ex_exceptions3','ex','clang','clang++','-O3')
    def test_functions_false_pointer_array_clang(self): self.check_function_inference(ex_dir/'ex_false_pointer_array','ex','clang','clang++','-O3')
    def test_functions_float_clang(self): self.check_function_inference(ex_dir/'ex_float','ex','clang','clang++','-O3')
    def test_functions_fprintf_clang(self): self.check_function_inference(ex_dir/'ex_fprintf','ex','clang','clang++','-O3')
    def test_functions_getoptlong_clang(self): self.check_function_inference(ex_dir/'ex_getoptlong','ex','clang','clang++','-O3')
    def test_functions_memberPointer_clang(self): self.check_function_inference(ex_dir/'ex_memberPointer','ex','clang','clang++','-O3')
    def test_functions_noreturn_clang(self): self.check_function_inference(ex_dir/'ex_noreturn','ex','clang','clang++','-O3')
    def test_functions_pointerReatribution_clang(self): self.check_function_inference(ex_dir/'ex_pointerReatribution','ex','clang','clang++','-O3')
    def test_functions_pointerReatribution2_clang(self): self.check_function_inference(ex_dir/'ex_pointerReatribution2','ex','clang','clang++','-O3')
    def test_functions_pointerReatribution3_clang(self): self.check_function_inference(ex_dir/'ex_pointerReatribution3','ex','clang','clang++','-O3')
    def test_functions_stat_clang(self): self.check_function_inference(ex_dir/'ex_stat','ex','clang','clang++','-O3')
    def test_functions_struct_clang(self): self.check_function_inference(ex_dir/'ex_struct','ex','clang','clang++','-O3')
    def test_functions_switch_clang(self): self.check_function_inference(ex_dir/'ex_switch','ex','clang','clang++','-O3')
    def test_functions_uninitialized_data_clang(self): self.check_function_inference(ex_dir/'ex_uninitialized_data','ex','clang','clang++','-O3')
    def test_functions_virtualDispatch_clang(self): self.check_function_inference(ex_dir/'ex_virtualDispatch','ex','clang','clang++','-O3')


    def check_in_function(self,make_dir):
        """
        Check that function analysis assigns all blocks to a function unless they are padding blocks.
        """
        with cd(make_dir):
            self.assertTrue(compile('gcc','g++','-O0',[]))
            self.assertTrue(disassemble('ex',False,format='--ir',extension='gtirb',
                extra_args=['--skip-function-analysis']))
            module = gtirb.IR.load_protobuf('ex.gtirb').modules[0]
            function_blocks = module.aux_data.get('functionBlocks').data
            padding = set(module.aux_data.get('padding').data.keys())
            blocks_in_function = {block for block_set in function_blocks.values() for block in block_set}
            for block in module.blocks:
                assert (block in blocks_in_function) or (block.address in padding)

    def test_in_function_no_cfi(self):
        self.check_in_function(asm_dir/'ex_switch_in_code_no_cfi')

    def test_in_function_with_cfi(self):
        self.check_in_function(asm_dir/'ex_switch_in_code')


if __name__ == '__main__':
    unittest.main()
