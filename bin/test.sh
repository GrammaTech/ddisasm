
# The first argument is the directory that contains the project with a makefile
# The makefile should have a "clean" goal 
Dir=$1
# The second argument is the name of the generated executable
exe_name=$2

# As an optional third argument we can give 'stripped' to analyzed the stripped binary

##
#
# Examples:
# ./test.sh ../examples/ex_switch ex_switch 
#
# ./test.sh ../examples/ex_switch ex_switch stripped
#
build="make -C $Dir"



echo " compiling example "

$build


if [ "$3" = "stripped" ]
then
    strip --strip-unneeded -o $Dir/$exe_name.stripped $Dir/$exe_name
    echo "Calling the disassembler on $Dir/$exe_name.stripped and storing the result in $Dir/result "
    ./disasm $Dir/$exe_name.stripped -hints > $Dir/result
else
    echo "Calling the disassembler on $Dir/$exe_name and storing the result in $Dir/result "
    ./disasm $Dir/$exe_name -hints > $Dir/result
    
fi

#./disasm $Dir/$exe_name -hints > $Dir/result

echo "Cleaning the build"
make  -C $Dir clean


echo "Calling DVT with the user hints $Dir/hints"
/code/trunk/gtx/bin/gtm --ir_path $Dir/CSURF_FILES_DVT --swyx user_hints=hints -- $build 

weird_code=$(ls $Dir/CSURF_FILES_DVT/ | grep $exe_name.*.festore.swx_sum)
weird_code=${weird_code%.swx_sum}

echo "Comparing results and storing results in $Dir/diffs.log"
/code/trunk/swyx/bin/gtir_compare  $Dir/CSURF_FILES_DVT/$weird_code $exe_name $Dir/CSURF_FILES_DVT/$weird_code $exe_name -l $Dir/diffs.log -1 dvt -2 user_labels


echo "Storing only the differences in $Dir/diffs_short.log"
cat $Dir/diffs.log | grep -e "^+" -e "^-" -e "^==" > $Dir/diffs_short.log

