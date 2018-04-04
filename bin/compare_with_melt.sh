
# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal
dir=$1
# The second argument is the name of the generated executable
exe=$2
exename=$(basename $exe)
exedir=$(dirname $exe)

dvt="no"
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
exename=$exename.stripped

echo "Calling the disassembler on $dir/$exe.stripped and storing the result in $dir/result "
./disasm $dir/$exe.stripped -asm -hints > $dir/$exe.s


cd $dir/$exedir
echo "Calling DVT with the user hints $dir/hints"

weird_code="store"

if [[ $dvt == "yes" ]]; then
    echo "Cleaning the build"
    make  -C $dir clean
    echo "Melting with DVT"
    /code/trunk/gtx/bin/gtm --ir_path $dir/CSURF_FILES  -- $build
    weird_code=$(ls $dir/CSURF_FILES/ | grep $exename.*.festore.swx_sum)
    weird_code=${weird_code%.swx_sum}
else
    echo "Melting without DVT"
    /code/trunk/gtx/bin/gtm --ir_path $dir/CSURF_FILES  --targets $exename
fi

echo "Melting with datalog hints"
/code/trunk/gtx/bin/gtm --ir_path $dir/CSURF_FILES_MINE  --swyx user_hints=$dir/$exedir/hints --targets $exename



echo "Comparing results and storing results in $dir/diffs.diff"
#/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES_DVT/$weird_code $exename $dir/CSURF_FILES_MINE/$weird_code2 $exename -l $dir/diffs.diff -1 dvt -2 user_labels -e

#compare with the IR
/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES/$weird_code $exename $dir/CSURF_FILES_MINE/store $exename -l $dir/diffs.diff  -2 user_labels -e

echo "/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES/$weird_code $exename $dir/CSURF_FILES_MINE/store $exename -l $dir/diffs.diff  -2 user_labels -e"


echo "Filtering differences"

diffs=$(cat $dir/diffs.diff | grep "^==" | grep -v -e  "==WARNING: no AST for EA" -e "==Mismatch ranges" -e "==Mismatch label"  -e "AddrConst displacement" -e "==WARNING: hints for unprintable" -e "StackConst displacement" -e "kind(OPK_STACKCONST, OPK_NONE)" -e "kind(OPK_NONE, OPK_STACKCONST)")

other_diffs=$(awk 'BEGIN{lastline=""} \
{                                     \
if($0 ~/^-/ && $0 !~/operands|data_range|data labels/ ){ \
   if(lastline!=""){          \
          print lastline;     \
          print $0;           \
   }else{                     \
          lastline=$0         \
   }                          \
 }else{                       \
   lastline=""                \
 }                            \
}'  $dir/diffs.diff)

if [[ $diffs == "" ]]; then
   printf "# ${green}Testing SUCCEED ${normal}\n\n"
else
    printf "# ${red}Testing FAILED ${normal}\n\n"
    echo "$diffs"
fi


if [[ $other_diffs == "" ]]; then
   printf "# ${green}Testing SUCCEED ${normal}\n\n"
else
    printf "# ${red}Testing FAILED ${normal}\n\n"
    echo "$other_diffs"
fi
