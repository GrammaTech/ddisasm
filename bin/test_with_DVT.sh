
# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal 
dir=$1
# The second argument is the name of the generated executable
exe=$2
exename=$(basename $exe)
exedir=$(dirname $exe)
# As an optional third argument we can give 'stripped' to analyzed the stripped binary

##
#
# Examples:
# ./test.sh ../examples/ex_switch ex_switch 
#

build="make -e -C $dir"

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`

printf "# Rebuilding project $dir\n"
if !( make clean -e -C $dir &>/dev/null  && make -e -C $dir &>/dev/null); then
    printf "# ${red}Initial compilation failed${normal}\n"
    exit 1
fi


strip --strip-unneeded -o $dir/$exe.stripped $dir/$exe
echo "Calling the disassembler on $dir/$exe.stripped and storing the result in $dir/result "
./disasm $dir/$exe.stripped -debug -hints > $dir/$exe.s


echo "Cleaning the build"
make  -C $dir clean


echo "Calling DVT with the user hints $dir/hints"
/code/trunk/gtx/bin/gtm --ir_path $dir/CSURF_FILES_DVT  --swyx user_hints=$exedir/hints -- $build 

weird_code=$(ls $dir/CSURF_FILES_DVT/ | grep $exename.*.festore.swx_sum)
weird_code=${weird_code%.swx_sum}

echo "Comparing results and storing results in $dir/diffs.diff"
/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES_DVT/$weird_code $exename $dir/CSURF_FILES_DVT/$weird_code $exename -l $dir/diffs.diff -1 dvt -2 user_labels -e 
echo "/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES_DVT/$weird_code $exename $dir/CSURF_FILES_DVT/$weird_code $exename -l $dir/diffs.diff -1 dvt -2 user_labels -e"


echo "Filtering differences"

diffs=$(cat $dir/diffs.diff | grep "^==" | grep -v -e  "==WARNING: no AST for EA" -e "==Mismatch ranges" -e "==Mismatch label"  -e "AddrConst displacement" -e "==WARNING: hints for unprintable")

if [[ $diffs == "" ]]; then
   printf "# ${green}Testing SUCCEED ${normal}\n\n"
else
    printf "# ${green}Testing FAILED ${normal}\n\n"
    echo "$diffs" | head
fi

       

