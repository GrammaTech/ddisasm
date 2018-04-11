
function compare_functions(){
    diff $1 $2 > $3
    missing=$( cat $3 | grep "<" | wc -l)
    extra=$( cat $3 | grep ">" | wc -l)

    if [[ $missing == "0" ]]; then
	echo "#$green No missing functions $normal"
    else
	echo "#$red $missing functions missing $normal"
    fi
    if [[ $extra == "0" ]]; then
	echo "#$green No extra functions $normal"
    else
	echo "#$red $extra extra functions that should not be there $normal"
    fi
    if [[ $missing != "0" || $extra != "0" ]]; then
	echo "#$red Differences: $normal"
	colordiff $1 $2
    else
	echo "#$green Test SUCCEED $normal"

    fi

}

# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal
dir=$1
# The second argument is the name of the generated executable
exe=$2
exename=$(basename $exe)
exedir=$(dirname $exe)

build="make -e -C $dir"

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

printf "# Rebuilding project $dir\n"
if !( make clean -e -C $dir &>/dev/null  && make -e -C $dir &>/dev/null); then
    printf "# ${red}Initial compilation failed${normal}\n"
    exit 1
fi

printf "# Stripping binary\n"
strip --strip-unneeded -o $dir/$exe.stripped $dir/$exe


echo "Calling the disassembler on $exe.stripped and storing the result in $dir/$exe.s "
./disasm $dir/$exe.stripped -debug -function_hints  > $dir/$exe.s
#./disasm $dir/$exe.stripped -debug -function_hints  > $dir/$exe.s

bin_dir=$(pwd)
cd $dir/$exedir


echo "Melting unstripped binary"
/code/trunk/gtx/bin/gtm --ir_path ./CSURF_FILES  --targets $exename
echo "Getting gtm functions"
/code/trunk/csurf/bin/csurf -nogui $exename.prj < $bin_dir/get_functions.stk | cut -d ' ' -f 2 | sort > swyx_functions.txt

echo "#Comparing functions with swyx results in $dir/functions_diff.diff"
compare_functions "swyx_functions.txt" "datalog_disasm_functions.txt" "functions_diff.diff"

exename=$exename.stripped

echo "Melting stripped binary"
/code/trunk/gtx/bin/gtm --ir_path ./CSURF_FILES_STRIPPED  --targets $exename
echo "Getting gtm functions"
/code/trunk/csurf/bin/csurf -nogui $exename.prj < $bin_dir/get_functions.stk | cut -d ' ' -f 2 | sort > swyx_stripped_functions.txt

echo "#Comparing functions with swyx stripped results in $dir/functions_diff_stripped.diff"
compare_functions "swyx_stripped_functions.txt" "datalog_disasm_functions.txt" "functions_diff_stripped.diff"






