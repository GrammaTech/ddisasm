
# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal 

dir=$1

shift
exe=$(basename "$dir")




main_dir=$(pwd)
cd $dir
build.sh $exe $@
cd $main_dir

red=`tput setaf 1`
green=`tput setaf 2`
normal=`tput sgr0`




strip --strip-unneeded -o $dir/$exe.stripped $dir/$exe
echo "Calling the disassembler on $dir/$exe.stripped and storing the result in $dir/result "
./disasm $dir/$exe.stripped -debug -hints > $dir/$exe.s


cd $dir
echo "Calling DVT with the user hints $dir/hints"
/code/trunk/gtx/bin/gtm --ir_path $dir/CSURF_FILES_DVT  --swyx user_hints=$dir/hints -- build.sh $exe $@

cd $main_dir

weird_code=$(ls $dir/CSURF_FILES_DVT/ | grep $exe.*.festore.swx_sum)
weird_code=${weird_code%.swx_sum}

echo "Comparing results and storing results in $dir/diffs.diff"
/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES_DVT/$weird_code $exe $dir/CSURF_FILES_DVT/$weird_code $exe -l $dir/diffs.diff -1 dvt -2 user_labels -e 
echo "/code/trunk/swyx/bin/gtir_compare  $dir/CSURF_FILES_DVT/$weird_code $exe $dir/CSURF_FILES_DVT/$weird_code $exe -l $dir/diffs.diff -1 dvt -2 user_labels -e"


echo "Filtering differences"

diffs=$(cat $dir/diffs.diff | grep "^==" | grep -v -e  "==WARNING: no AST for EA" -e "==Mismatch ranges" -e "==Mismatch label"  -e "AddrConst displacement" -e "==WARNING: hints for unprintable")

if [[ $diffs == "" ]]; then
   printf "# ${green}Testing SUCCEED ${normal}\n\n"
else
    printf "# ${green}Testing FAILED ${normal}\n\n"
    echo "$diffs" | head
fi

       

