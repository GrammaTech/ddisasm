import argparse
import contextlib
import os
import shlex
import subprocess
from timeit import default_timer as timer

class bcolors:
    """
    Define some colors for printing in the terminal
    """
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    @classmethod
    def okblue(cls, *args):
        return cls.OKBLUE + ' '.join(args) + cls.ENDC

    @classmethod
    def okgreen(cls, *args):
        return cls.OKGREEN + ' '.join(args) + cls.ENDC

    @classmethod
    def warning(cls, *args):
        return cls.WARNING + ' '.join(args) + cls.ENDC

    @classmethod
    def fail(cls, *args):
        return cls.FAIL + ' '.join(args) + cls.ENDC



def compile(compiler,cpp_compiler,optimizations,extra_flags):
    """
    Clean the project and compile it using the compiler
    'compiler', the cxx compiler 'cpp_compiler' and the flags in
    'optimizations' and 'extra_flags'
    """
    def quote_args(*args):
        return ' '.join(shlex.quote(arg) for arg in args)
    # Copy the current environment and modify the copy.
    env = dict(os.environ)
    env['CC'] = compiler
    env['CXX'] = cpp_compiler
    env['CFLAGS'] = quote_args(optimizations, *extra_flags)
    env['CXXFLAGS'] = quote_args(optimizations, *extra_flags)
    completedProcess = subprocess.run(['make', 'clean', '-e'], env=env, stdout=subprocess.DEVNULL)
    if completedProcess.returncode == 0:
        completedProcess = subprocess.run(['make', '-e'], env=env, stdout=subprocess.DEVNULL)
    return completedProcess.returncode==0

@contextlib.contextmanager
def get_target(binary,strip):
    if strip:
            print('# stripping binary\n')
            subprocess.run(['cp',binary,binary+'.stripped'])
            binary=binary+'.stripped'
            subprocess.run(['strip','--strip-unneeded',binary])
    try:
        yield binary
    finally:
        if strip:
            os.remove(binary)

def dissasemble(binary,strip):
    """
    Disassemble the binary 'binary'
    """
    with get_target(binary,strip) as target_binary:
        print('# Disassembling '+target_binary+'\n')
        start=timer()
        completedProcess=subprocess.run(['ddisasm',target_binary,'--asm',binary+'.s'])
        time_spent=timer()-start
    if completedProcess.returncode==0:
        print(bcolors.okgreen('Disassembly succeed'),flush=True)
        return True,time_spent
    else:
        print(bcolors.fail('Disassembly failed'),flush=True)
        return False,time_spent

def reassemble(compiler,binary,extra_flags):
    """
    Reassemble the assembly file binary+'.s' into a new binary
    """
    print("# Reassembling", binary + ".s", "into", binary)
    print("compile command:", compiler, binary + '.s', '-o', binary, *extra_flags)
    completedProcess=subprocess.run([compiler,binary+'.s','-o',binary]+extra_flags)
    if(completedProcess.returncode!=0):
        print(bcolors.warning('# Reassembly failed\n'))
        return False
    print(bcolors.okgreen("# Reassembly succeed"))
    return True

def test():
    """
    Test the project with  'make check'.
    """
    print("# testing\n")
    completedProcess=subprocess.run(['make','check','-e'], stderr=subprocess.DEVNULL)
    if(completedProcess.returncode!=0):
        print(bcolors.warning('# Testing FAILED\n'))
        return False
    else:
        print(bcolors.okgreen('# Testing SUCCEED\n'))
        return True

def disassemble_reassemble_test(make_dir,binary,
                                extra_compile_flags=[],
                                extra_reassemble_flags=[],
                                reassembly_compiler='gcc',
                                c_compilers=['gcc','clang'],
                                cxx_compilers=['g++','clang++'],
                                optimizations=['-O0','-O1','-O2','-O3','-Os'],
                                strip=False,
                                skip_reassemble=False,
                                skip_test=False):
    """
    Disassemble, reassemble and test an example with the given compilers and optimizations.
    """
    compile_errors=0
    disassembly_errors=0
    reassembly_errors=0
    test_errors=0
    current_dir=os.getcwd()
    os.chdir(make_dir)
    for compiler,cpp_compiler in zip(c_compilers,cxx_compilers):
        for optimization in optimizations:
            print(bcolors.okblue('Project', make_dir, 'with', compiler,'and', optimization, *extra_compile_flags))
            if not compile(compiler,cpp_compiler,optimization,extra_compile_flags):
                compile_errors+=1
                continue
            success,time= dissasemble(binary,strip)
            print("Time "+str(time))
            if not success:
                disassembly_errors+=1
                continue
            if skip_reassemble:
                print(bcolors.warning(" No reassemble"))
                continue
            if not reassemble(reassembly_compiler,binary,extra_reassemble_flags):
                reassembly_errors+=1
                continue
            if skip_test:
                print(bcolors.warning(" No testing"))
                continue
            if not test():
                test_errors+=1
    os.chdir(current_dir)
    total_errors=compile_errors+disassembly_errors+reassembly_errors+test_errors
    return total_errors==0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Disassemble reassemble and test a project with ddisasm')
    parser.add_argument('make_dir', help='project to test')
    parser.add_argument('binary', help='binary within the project')
    parser.add_argument('--extra_compile_flags',nargs="*",type=str,default=[])
    parser.add_argument('--extra_reassemble_flags',nargs="*",type=str,default=[])
    parser.add_argument('--reassembly_compiler',type=str,default='gcc')
    parser.add_argument('--c_compilers',nargs="*" ,type=str,default=['gcc','clang'])
    parser.add_argument('--cxx_compilers',nargs="*" ,type=str,default=['g++','clang++'])
    parser.add_argument('--optimizations',nargs="*",type=str,default=['-O0','-O1','-O2','-O3','-Os'])
    parser.add_argument('--strip', help='strip binaries before disassembling',action='store_true',default=False)
    parser.add_argument('--skip_test', help='skip testing', action='store_true')
    parser.add_argument('--skip_reassemble', help='skip reassemble', action='store_true')

    args = parser.parse_args()
    disassemble_reassemble_test(**args.__dict__)