
function compare_functions(){
    diff $1 $2 > $3
    missing=$( cat $3 | grep "<" | wc -l)
    extra=$( cat $3 | grep ">" | wc -l)
    total=$( cat $1 | wc -l)
    echo "#$4  $total Functions"
    if [[ $missing == "0" ]]; then
	echo "#$4 $green EQUAL $normal"
    else
	echo "#$4 $red $missing FALSE NEGATIVES $normal"
    fi
    if [[ $extra == "0" ]]; then
	echo "#$$4 green EQUAL $normal"
    else
	echo "#$4 $red $extra FALSE POSITIVES $normal"
    fi
    if [[ $missing != "0" || $extra != "0" ]]; then
	echo "#$4 $red Differences: $normal"
	colordiff $1 $2
    else
	echo "#$4 $green Test SUCCEED $normal"

    fi
    echo "###$4 $missing $extra $total"

}
datalog="no"
if [[ $# > 0 && $1 == "-dl" ]]; then
    datalog=1
    shift
fi
melt="no"
if [[ $# > 0 && $1 == "-melt" ]]; then
    melt=1
    shift
fi
# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal
dir=$1
# The second argument is the name of the generated executable
exe=$2
exename=$(basename $exe)
exedir=$(dirname $exe)
bin_dir=$(pwd)
build="make -e -C $dir"

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

qualifier="$CC$CFLAGS"

export CFLAGS="-g  $CFLAGS"

printf "# Rebuilding project (with debug flag) $dir\n"
if !( make clean -e -C $dir &>/dev/null  && make -e -C $dir &>/dev/null); then
    printf "# ${red}Initial compilation failed${normal}\n"
    exit 1
fi


echo "#getting functions symbols of the original binary"
readelf $dir/$exe -s | grep " FUNC " | grep -v " UND " | cut -c 9-24 | awk '{sub("^0*","",$0); print}' | sort -u >$dir/$exedir/readelf_functions.txt


printf "# Stripping binary\n"
strip --strip-unneeded -o $dir/$exe.stripped $dir/$exe



if [ $datalog == 1 ]; then
    echo "Calling the disassembler on $exe.stripped and storing the result in $dir/$exe.s "
    ./disasm $dir/$exe.stripped -debug -function_hints  > $dir/$exe.s
    
    echo "#Comparing functions with readelf symbols"
    compare_functions "$dir/$exedir/readelf_functions.txt" "$dir/$exedir/datalog_disasm_functions_in_text.txt" "$dir/$exedir/functions_diff2.diff" "dl-$qualifier"

fi

cd $dir/$exedir
# echo "Melting unstripped binary"
# /code/trunk/gtx/bin/gtm --ir_path ./CSURF_FILES  --targets $exename
# echo "Getting gtm functions"
# /code/trunk/csurf/bin/csurf -nogui $exename.prj < $bin_dir/get_functions.stk | grep -v -e "thunk_at_" -e "__thunk"   | cut -d ' ' -f 2 | sort > swyx_functions.txt


exename=$exename.stripped	

if [ $melt == 1 ]; then
    echo "Melting stripped binary"
    /code/trunk/gtx/bin/gtm --ir_path ./CSURF_FILES_STRIPPED  --targets $exename
    echo "Getting gtm functions"
    /code/trunk/csurf/bin/csurf -nogui $exename.prj < $bin_dir/get_functions.stk | grep -v -e "thunk_at_" -e "__thunk" | cut -d ' ' -f 2 | sort > swyx_stripped_functions.txt

    echo "#Comparing readelf info with swyx stripped results"
    compare_functions "readelf_functions.txt" "swyx_stripped_functions.txt" "functions_diff_stripped.diff" "swyx-$qualifier"

fi




