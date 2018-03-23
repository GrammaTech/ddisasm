
if [[ $# -eq 0 || $1 == "-h" || $1 == "--help" ]]; then
    printf "USAGE: ./reassemble_and_test.sh project_directory binary_path [compiler_flags]
 Take a project directory where the main makefile is located
 and the relative path of the main executable within the directory and:
 -Rebuild the project
 -Disassemble the binary
 -Reassemble the binary (substituting the old one and saving the old one in 'binary'.old)
 -Run the makefile's tests

 The reassembly uses the 'compiler_flags' arguments

 Example:
 ./reasemble_and_test.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre

-The assembly code will be in ../real_world_examples/grep-2.5.4/src/grep.s
-The old binary will be  ../real_world_examples/grep-2.5.4/src/grep.old
"   
    exit
fi

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

strip=0
if [[ $# > 0 && $1 == "-strip" ]]; then
    strip=1
    shift
fi

stir=""
if [[ $# > 0 && $1 == "-stir" ]]; then
    stir="-stir"
    shift
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
if !( make clean -e -C $dir &>/dev/null  && make -e -C $dir &>/dev/null); then
    printf "# ${red}Initial compilation failed${normal}\n"
    exit 1
fi

if [ $strip == 1 ]; then 
    printf "# Stripping binary\n"
    cp "$dir/$exe" "$dir/$exe.unstripped"
    strip --strip-unneeded "$dir/$exe"
fi

printf "# Disassembling $exe into $exe.s with flags: $stir\n"
if !(time(./disasm "$dir/$exe" -asm $stir > "$dir/$exe.s") 2>/tmp/time.txt); then
    printf "# ${red}Disassembly failed${normal}\n"
    exit 1
fi
decode_time=$(cat /tmp/time.txt | grep -m 1 seconds)
dl_time=$(cat /tmp/time.txt | grep -m 2 seconds | tail -n1)
decode_time=${decode_time#*in }
decode_time=${decode_time%seconds*}
dl_time=${dl_time#*in }
dl_time=${dl_time%seconds*}

time=$(cat /tmp/time.txt| grep user| cut -f 2)
size=$(stat --printf="%s" "$dir/$exe")
printf "#Stats: Time $time Decode $decode_time Datalog $dl_time Size $size\n"

printf "  OK\n"
printf "Copying old binary to $dir/$exe.old\n"
cp $dir/$exe $dir/$exe.old
printf "# Reassembling...\n"

if !($compiler "$dir/$exe.s" $@ -o  "$dir/$exe"); then
    printf "# ${red}Reassembly failed ${normal}\n"
    exit 1
fi

printf "  OK\n"
printf "# Testing\n"
if !(make check -C $dir); then
    printf "# ${red}Testing FAILED ${normal}\n\n"
else
    printf "# ${green}Testing SUCCEED ${normal}\n\n"
fi



