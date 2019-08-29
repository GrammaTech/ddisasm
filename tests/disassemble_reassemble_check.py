from timeit import default_timer as timer
import os
import subprocess
import argparse

class bcolors:
    """
    Define some colors for printing in the terminal
    """
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def compile(compiler,cpp_compiler,optimizations,extra_flags):
    """
    Clean the project and compile it using the compiler
    'compiler', the cxx compiler 'cpp_compiler' and the flags in
    'optimizations' and 'extra_flags'
    """
    os.environ['CC'] = compiler
    os.environ['CXX'] = cpp_compiler
    os.environ['CFLAGS'] = optimizations +' '+ ' '.join(extra_flags)
    os.environ['CXXFLAGS'] = optimizations +' '+ ' '.join(extra_flags)
    subprocess.run(['make','clean','-e'])
    completedProcess=subprocess.run(['make','-e'])
    os.environ.pop('CC',None)
    os.environ.pop('CXX',None)
    os.environ.pop('CFLAGS',None)
    os.environ.pop('CXXFLAGS',None)
    return completedProcess.returncode==0

def dissasemble(binary,strip):
    """
    Disassemble the binary 'binary'
    """
    target_binary=binary
    if strip:
        print('# stripping binary\n')
        subprocess.run(['cp',binary,binary+'.stripped'])
        target_binary=binary+'.stripped'
        subprocess.run(['strip','--strip-unneeded',target_binary])
    print('# Disassembling '+target_binary+'\n')
    start=timer()
    completedProcess=subprocess.run(['ddisasm',target_binary,'--asm',binary+'.s'], stderr=subprocess.PIPE)
    time_spent=timer()-start
    if completedProcess.returncode==0:
        print(bcolors.OKGREEN+'Disassembly succeed\n'+bcolors.ENDC,flush=True)
        return True,time_spent
    else:
        print(bcolors.FAIL+'Disassembly failed\n'+bcolors.ENDC,flush=True)
        return False,time_spent

def reassemble(compiler,binary,extra_flags):
    """
    Reassemble the assembly file binary+'.s' into a new binary
    """
    print("# Reassembling "+binary+ ".s into "+ binary)
    print("compile command: "+' '.join([compiler,binary+'.s','-o',binary]+extra_flags))
    completedProcess=subprocess.run([compiler,binary+'.s','-o',binary]+extra_flags)
    if(completedProcess.returncode!=0):
        print(bcolors.WARNING+'# Reassembly failed\n'+bcolors.ENDC)
        return False
    print(bcolors.OKGREEN+"# Reassembly succeed"+bcolors.ENDC)
    return True

def test():
    """
    Test the project with  'make check'.
    """
    print("# testing\n")
    completedProcess=subprocess.run(['make','check','-e'], stderr=subprocess.PIPE)
    if(completedProcess.returncode!=0):
        print(bcolors.WARNING+'# Testing FAILED\n'+bcolors.ENDC)
        return False
    else:
        print(bcolors.OKGREEN+'# Testing SUCCEED\n'+bcolors.ENDC)
        return True

def disassemble_reassemble_test(make_dir,binary,
                                extra_compile_flags=[],
                                extra_reassemble_flags=[],
                                reassembly_compiler='gcc',
                                compilers=[('gcc','g++'),('clang','clang++')],
                                optimizations=['-O0','-O1','-O2','-O3','-Os'],
                                strip=False,
                                should_reassemble=True,
                                should_test=True):
    """
    Disassemble, reassemble and test an example with the given compilers and optimizations.
    """
    compile_errors=0
    disassembly_errors=0
    reassembly_errors=0
    test_errors=0
    current_dir=os.getcwd()
    os.chdir(make_dir)
    for compiler,cpp_compiler in compilers:
        for optimization in optimizations:
            print(bcolors.OKBLUE+ 'Project '+make_dir+' with '+ compiler+' and '+ optimization+' '+' '.join(extra_compile_flags)+bcolors.ENDC)
            if not compile(compiler,cpp_compiler,optimization,extra_compile_flags):
                compile_errors+=1
                continue
            success,time= dissasemble(binary,strip)
            print("Time "+str(time))
            if not success:
                disassembly_errors+=1
                continue
            if not should_reassemble:
                print(bcolors.WARNING+ " No reassemble"+bcolors.ENDC)
                continue
            if not reassemble(reassembly_compiler,binary,extra_reassemble_flags):
                reassembly_errors+=1
                continue
            if not should_test:
                print(bcolors.WARNING+ " No testing"+bcolors.ENDC)
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
    parser.add_argument('--cpp_compilers',nargs="*" ,type=str,default=['g++','clang++'])
    parser.add_argument('--optimizations',nargs="*",type=str,default=['-O0','-O1','-O2','-O3','-Os'])
    parser.add_argument('--strip', help='strip binaries before disassembling',action='store_true',default=False)
    parser.add_argument('--skip_test', help='skip testing', action='store_true')
    parser.add_argument('--skip_reassemble', help='skip reassemble', action='store_true')

    args = parser.parse_args()
    disassemble_reassemble_test(args.make_dir,args.binary,
        extra_compile_flags=args.extra_compile_flags,
        extra_reassemble_flags=args.extra_reassemble_flags,
        reassembly_compiler=args.reassembly_compiler,
        compilers=zip(args.c_compilers,args.cpp_compilers),
        optimizations=args.optimizations,
        strip=args.strip,
        should_reassemble= not args.skip_reassemble,
        should_test= not args.skip_test)