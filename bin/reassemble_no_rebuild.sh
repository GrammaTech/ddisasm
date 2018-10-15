



if [[ $# -eq 0 || $1 == "-h" || $1 == "--help" ]]; then
    printf "USAGE: ./reassemble_no_rebuild.sh project_directory binary_path [compiler_flags]
 Take a project directory where the main makefile is located
 and the relative path of the main executable within the directory and:
 -Disassemble the binary
 -Reassemble the binary (substituting the old one)

 The reassembly uses the 'compiler_flags' arguments

 Example:
 ./reasemble_no_rebuild.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre
"   
    exit
fi

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

if [[ $# > 0 && $1 == "-strip" ]]; then
    strip=1
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


if [ $strip ]; then 
    printf "# Stripping binary\n"
    cp "$dir/$exe" "$dir/$exe.unstripped"
    strip --strip-unneeded "$dir/$exe"
fi

printf "# Disassembling $exe into $exe.s\n"
dl_files_dir=$(dirname $dir/$exe)/dl_files/
mkdir "$dl_files_dir"
if !(time(ddisasm "$dir/$exe" --debug-dir "$dl_files_dir" --asm  "$dir/$exe.s" > "$dir/disasm.out") 2>/tmp/timeCore.txt); then
    printf "# ${red}Disassembly failed${normal}\n"
    exit 1
fi
time=$(cat /tmp/timeCore.txt| grep user| cut -f 2)
size=$(stat --printf="%s" "$dir/$exe")
printf "#Stats: Time $time Size $size\n"

printf "  OK\n"
printf "Copying old binary to $dir/$exe.old\n"
cp $dir/$exe $dir/$exe.old
binary_type=$(cat $dl_files_dir/binary_type.facts)
printf "# Binary of type $binary_type\n"

pie_flag=""
if [[  $binary_type == "DYN" ]]; then
    pie_flag="-pie"
else
    pie_flag="-no-pie"
fi

printf "# Reassembling...\n"

if !($compiler "$dir/$exe.s" $pie_flag $@ -o  "$dir/$exe"); then
    printf "# ${red}Reassembly failed ${normal}\n"
    exit 1
fi
printf "  OK\n"




