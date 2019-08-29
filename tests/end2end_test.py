import unittest
from disassemble_reassemble_check import disassemble_reassemble_test as dis_reasm_test

ex_dir='./examples/'
asm_dir='./examples/asm_examples/'

class TestSmall(unittest.TestCase):
    def test_1(self): self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex'))
    def test_2modulesPIC(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_2modulesPIC','ex'))
    def test_confusing_data(self): self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex'))
    def test_exceptions1(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions1','ex',reassembly_compiler='g++'))
    def test_exceptions2(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions2','ex',reassembly_compiler='g++'))
    def test_exceptions3(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions3','ex',reassembly_compiler='g++'))
    def test_false_pointer_array(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_false_pointer_array','ex'))
    def test_float(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_float','ex'))
    def test_fprintf(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_fprintf','ex'))
    def test_getoptlong(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_getoptlong','ex'))
    def test_memberPointer(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_memberPointer','ex',reassembly_compiler='g++'))
    def test_noreturn(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_noreturn','ex'))
    def test_pointerReatribution(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution','ex'))
    def test_pointerReatribution2(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution2','ex'))
    def test_pointerReatribution3(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution3','ex'))
    def test_stat(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_stat','ex'))
    def test_struct(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_struct','ex'))
    def test_switch(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_switch','ex'))
    def test_uninitialized_data(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_uninitialized_data','ex'))
    def test_virtualDispatch(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_virtualDispatch','ex',reassembly_compiler='g++'))

    # Examples that fail the tests
    #thread local storage
    def test_threads(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_threads','ex',reassembly_compiler='g++',
        should_test=False,extra_reassemble_flags=['-lpthread']))

    # Examples that fail to reassemble
    #static binary with libc
    def test_ex1_static(self):
        self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex',should_reassemble=False,
            extra_compile_flags=['-static'],
            compilers=[('gcc','g++')],
            optimizations=['']))

class TestSmallStrip(unittest.TestCase):
    def test_1(self): self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex',strip=True))
    def test_2modulesPIC(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_2modulesPIC','ex',strip=True))
    def test_confusing_data(self): self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex',strip=True))
    def test_exceptions1(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions1','ex',reassembly_compiler='g++',strip=True))
    def test_exceptions2(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions2','ex',reassembly_compiler='g++',strip=True))
    def test_exceptions3(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_exceptions3','ex',reassembly_compiler='g++',strip=True))
    def test_false_pointer_array(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_false_pointer_array','ex',strip=True))
    def test_float(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_float','ex',strip=True))
    def test_fprintf(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_fprintf','ex',strip=True))
    def test_getoptlong(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_getoptlong','ex',strip=True))
    def test_memberPointer(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_memberPointer','ex',reassembly_compiler='g++',strip=True))
    def test_noreturn(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_noreturn','ex',strip=True))
    def test_pointerReatribution(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution','ex',strip=True))
    def test_pointerReatribution2(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution2','ex',strip=True))
    def test_pointerReatribution3(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_pointerReatribution3','ex',strip=True))
    def test_stat(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_stat','ex',strip=True))
    def test_struct(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_struct','ex',strip=True))
    def test_switch(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_switch','ex',strip=True))
    def test_uninitialized_data(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_uninitialized_data','ex',strip=True))
    def test_virtualDispatch(self): self.assertTrue(dis_reasm_test(ex_dir+'ex_virtualDispatch','ex',reassembly_compiler='g++',strip=True))

class TestAsmExamples(unittest.TestCase):

    def test_asm_pointerReatribution3(self):
        self.assertTrue(dis_reasm_test(asm_dir+'ex_pointerReatribution3','ex',compilers=[('gcc','g++')],optimizations=['']))

    def test_asm_pointerReatribution3_clang(self):
        self.assertTrue(dis_reasm_test(asm_dir+'ex_pointerReatribution3_clang','ex',compilers=[('gcc','g++')],optimizations=['']))

    def test_asm_pointerReatribution3_pie(self):
        self.assertTrue(dis_reasm_test(asm_dir+'ex_pointerReatribution3_pie','ex',compilers=[('gcc','g++')],optimizations=['']))

    def test_asm_weird_section(self):
        self.assertTrue(dis_reasm_test(asm_dir+'ex_weird_sections','ex',compilers=[('gcc','g++')],optimizations=['']))

class TestSpecialFlags(unittest.TestCase):
    # test binary compiled with -fcf-protection
    def test_fcf_protection(self):
        self.assertTrue(dis_reasm_test(ex_dir+'ex1','ex',compilers=[('gcc','g++')],
            optimizations=[''],
            extra_compile_flags=['-fcf-protection']))


if __name__ == '__main__':
    unittest.main()
