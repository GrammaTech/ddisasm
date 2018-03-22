# ./reassemble_and_test.sh project_directory binary_path [compiler_flags]
# Take a project directory where the main makefile is located
# and the relative path of the main executable within the directory and:
# -Rebuild the project
# -Disassemble the binary
# -Reassemble the binary (substituting the old one)
# -Run the makefile's tests

# The reassembly uses the 'compiler_flags' arguments

# Example:
# ./CBC_reassemble_and_test.sh /code/cgc-cbs/cqe-challenges/CROMU_00001 -lm
#
#

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

if [[ $# -eq 0 || $1 == "-h" || $1 == "--help" ]]; then
    printf "USAGE: ./CBC_reassemble_and_test.sh cbc_challenge_dir  [compiler_flags]
 Take a directory of a cbc challenge:
 -build the binary with the compiler flags
 -Disassemble the binary
 -Reassemble the binary with the suffix _2
 -Run the tests on the initial binary
 -Run the tests on the new binary

 The reassembly uses the 'compiler_flags' arguments

 Example:
 ./CBC_reassemble_and_test.sh /code/cgc-cbs/cqe-challenges/CROMU_00001 gcc -O2
"   
    exit
fi

dir=$1
tests=/poller/for-release/
#tests=/poller/for-testing/
shift
exe=$(basename "$dir")
suffix="_2"
new_exe=$exe$suffix

compiler_reassembly="g++"

main_dir=$(pwd)
cd $dir
build.sh $exe $@
cd $main_dir

printf "#Disassembling $exe into $exe.s\n"
if !(time(./disasm "$dir/$exe" -asm -stir > "$dir/$exe.s") 2>/tmp/timeCGC.txt); then
    printf "Disassembly failed\n"
    exit 1
fi
decode_time=$(cat /tmp/timeCGC.txt | grep -m 1 seconds)
dl_time=$(cat /tmp/timeCGC.txt | grep -m 2 seconds | tail -n1)
decode_time=${decode_time#*in }
decode_time=${decode_time%seconds*}
dl_time=${dl_time#*in }
dl_time=${dl_time%seconds*}

time=$(cat /tmp/timeCGC.txt| grep user| cut -f 2)
size=$(stat --printf="%s" "$dir/$exe")
printf "#Stats: Time $time Decode $decode_time Datalog $dl_time Size $size\n"


printf "OK\n"
printf "# Reassembling  $exe.s into $new_exe \n"
if !($compiler_reassembly -nostartfiles "$dir/$exe.s" -lm -o  "$dir/$new_exe"); then
    echo "Reassembly failed"
    exit 1
fi

printf "#Testing of the original file\n"
cb-test --directory $dir --cb $exe --xml_dir $dir$tests  >/tmp/original.out

cat /tmp/original.out  | grep   -e "^\# total" -e "^\# polls" >/tmp/original_summary.out
cat /tmp/original_summary.out

printf "#Testing the new binary $new_exe \n"
cb-test --directory $dir --cb "$new_exe" --xml_dir $dir$tests  >/tmp/new.out
cat /tmp/new.out | grep   -e "^\# total" -e "^\# polls" > /tmp/new_summary.out
cat /tmp/new_summary.out

diff=$(diff /tmp/original_summary.out  /tmp/new_summary.out)
if [[ -z  $diff ]] ; then
    echo "# $green Testing SUCCEED $normal";
else
    echo "# $red Testing FAILED $normal"
    echo "$diff"
    exit 1
fi



