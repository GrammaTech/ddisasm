import platform
import unittest
from disassemble_reassemble_check import disassemble_reassemble_test as dis_reasm_test
from disassemble_reassemble_check import compile,cd
import os
from pathlib import Path

ex_dir=Path('./examples/')
asm_dir=Path('./examples/asm_examples/')

class TestSmall(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_1(self): self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_2modulesPIC(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_2modulesPIC','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_confusing_data(self): self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions1(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions1','ex',reassembly_compiler='g++'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions2(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions2','ex',reassembly_compiler='g++'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions3(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions3','ex',reassembly_compiler='g++'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_false_pointer_array(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_false_pointer_array','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_float(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_float','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_fprintf(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_fprintf','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_getoptlong(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_getoptlong','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_memberPointer(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_memberPointer','ex',reassembly_compiler='g++'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_noreturn(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_noreturn','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution2(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution2','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution3(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution3','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_stat(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_stat','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_struct(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_struct','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_switch(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_switch','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_uninitialized_data(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_uninitialized_data','ex'))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_virtualDispatch(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_virtualDispatch','ex',reassembly_compiler='g++'))

    # Examples that fail to reassemble

    #thread local storage
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_threads(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_threads','ex',reassembly_compiler='g++',skip_reassemble=True))

    #static binary with libc
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_ex1_static(self):
        self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex',skip_reassemble=True,
            extra_compile_flags=['-static'],
            c_compilers=['gcc'],
            cxx_compilers=['g++'],
            optimizations=['-O0']))

class TestSmallStrip(unittest.TestCase):
    # Linux tests
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_1(self): self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_2modulesPIC(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_2modulesPIC','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_confusing_data(self): self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions1(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions1','ex',reassembly_compiler='g++',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions2(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions2','ex',reassembly_compiler='g++',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_exceptions3(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_exceptions3','ex',reassembly_compiler='g++',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_false_pointer_array(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_false_pointer_array','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_float(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_float','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_fprintf(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_fprintf','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_getoptlong(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_getoptlong','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_memberPointer(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_memberPointer','ex',reassembly_compiler='g++',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_noreturn(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_noreturn','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution2(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution2','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_pointerReatribution3(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_pointerReatribution3','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_stat(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_stat','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_struct(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_struct','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_switch(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_switch','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_uninitialized_data(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_uninitialized_data','ex',strip=True))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_virtualDispatch(self): self.assertTrue(dis_reasm_test(ex_dir/'ex_virtualDispatch','ex',reassembly_compiler='g++',strip=True))

    # Windows tests
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_1_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex1', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_2modulesPIC_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_2modulesPIC', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_confusing_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_confusing_data', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_false_pointer_array_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_false_pointer_array', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_float_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_float', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))        

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_fprintf_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_fprintf', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_noreturn_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_noreturn', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_pointerReatribution_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_pointerReatribution', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))        

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_pointerReatribution2_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_pointerReatribution2', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))        

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_pointerReatribution3_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_pointerReatribution3', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))        
        
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_struct_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_struct', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))                

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_switch_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_switch', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
        
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_uninitialized_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_uninitialized_data', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_legacy_switch_001_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_legacy_switch.001', 'main.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))

    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_legacy_switch_002_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_legacy_switch.002', 'main.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_legacy_switch_003_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_legacy_switch.003', 'main.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_legacy_switch_004_data_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_legacy_switch.004', 'main.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    @unittest.skipUnless(platform.system() == 'Windows', 'This test is windows only.')
    def test_memberPointer_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_memberPointer', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
    def test_virtualDispatch_win(self):
        self.assertTrue(dis_reasm_test('..\examples\ex_virtualDispatch', 'ex.exe', [], ['/link', '/subsystem:console', '/entry:__EntryPoint'], 'ml64', ['cl'], ['cl'], ['/Od']))
        
class TestAsmExamples(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3_clang(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3_clang','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3_pie(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3_pie','ex',
            extra_compile_flags=['-pie'],
            c_compilers=['gcc'],
            cxx_compilers=['g++'],
            optimizations=['']))
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_weird_section(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_weird_sections','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_relative_switch(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_relative_switch','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_relative_switch_sizes(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_relative_switch_sizes','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code2(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code2','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code3(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code3','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

class TestAsmExamplesStrip(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3_clang(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3_clang','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_pointerReatribution3_pie(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_pointerReatribution3_pie','ex',
            extra_compile_flags=['-pie'],
            c_compilers=['gcc'],
            cxx_compilers=['g++'],
            optimizations=[''],
            strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_weird_section(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_weird_sections','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_relative_switch(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_relative_switch','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_relative_switch_sizes(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_relative_switch_sizes','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=['']))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code2(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code2','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_asm_switch_in_code3(self):
        self.assertTrue(dis_reasm_test(asm_dir/'ex_switch_in_code3','ex',c_compilers=['gcc'],cxx_compilers=['g++'],optimizations=[''],strip=True))

class TestSpecialFlags(unittest.TestCase):
    # test binary compiled with -fcf-protection
    @unittest.skipUnless(platform.system() == 'Linux', 'This test is linux only.')
    def test_fcf_protection(self):
        # check if the -fcf-protection is supported by the compiler (only newer versions support it)
        current_dir=os.getcwd()
        with cd(ex_dir/'ex1'):
            flag_supported=compile('gcc','g++','',['-fcf-protection'])
        if flag_supported:
            self.assertTrue(dis_reasm_test(ex_dir/'ex1','ex',
                c_compilers=['gcc'],cxx_compilers=['g++'],
                optimizations=[''],
                extra_compile_flags=['-fcf-protection']))
        else:
            print('Flag -fcf-protection not supported')


if __name__ == '__main__':
    unittest.main()
