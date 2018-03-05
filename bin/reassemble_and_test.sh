# ./reassemble_and_test.sh project_directory binary_path [compiler_flags]
# Take a project directory where the main makefile is located
# and the relative path of the main executable within the directory and:
# -Rebuild the project
# -Disassemble the binary
# -Reassemble the binary (substituting the old one)
# -Run the makefile's tests

# The reassembly uses the 'compiler_flags' arguments

# Example:
# ./reasemble_and_test.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre
#

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

if [[ $# -eq 0 || $1 == "-h" || $1 == "--help" ]]; then
    printf "USAGE: ./reassemble_and_test.sh project_directory binary_path [compiler_flags]
 Take a project directory where the main makefile is located
 and the relative path of the main executable within the directory and:
 -Rebuild the project
 -Disassemble the binary
 -Reassemble the binary (substituting the old one)
 -Run the makefile's tests

 The reassembly uses the 'compiler_flags' arguments

 Example:
 ./reasemble_and_test.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre
"   
    exit
fi
dir=$1
exe=$2
shift
shift
compiler="gcc"

if [[ $# > 0 && $1 == "g++" ]]; then
    compiler="g++"
    shift
fi


printf "# Rebuilding project $dir\n"
if !( make clean -e -C $dir &>/dev/null  && make -e -C $dir ); then
    printf "${red}Initial compilation failed${normal}\n"
    exit 1
fi

printf "# Disassembling $exe into $exe.s\n"
if !(time(./disasm "$dir/$exe" -asm > "$dir/$exe.s")); then
    printf "${red}Disassembly failed${normal}\n"
    exit 1
fi

printf "  OK\n"
printf "Copying old binary to $dir/$exe.old\n"
cp $dir/$exe $dir/$exe.old
printf "## Reassembling... "

if !($compiler "$dir/$exe.s" $@ -o  "$dir/$exe"); then
    echo "Reassembly failed \n"
    exit 1
fi

printf "  OK\n"
printf "# Testing\n"
if !(make check -C $dir); then
    printf "## ${red}Testing FAILED ${normal}\n\n"
else
    printf "## ${green}Testing SUCCEED ${normal}\n\n"
fi



