Dir=$(dirname $1)
echo "calling the disassembler" 
./disasm $1 -hints > $Dir/result

exe_name=$(basename $1)
#echo $Dir
echo "calling dvt with the user hints $Dir/hints" 
/code/trunk/gtx/bin/gtm --ir_path $Dir/CSURF_FILES_DVT --swyx user_hints=hints -- gcc $1.c -o $1

echo "listing generated files"
weird_code=$(ls $Dir/CSURF_FILES_DVT/ | grep $exe_name.*.festore.swx_sum)
weird_code=${weird_code%.swx_sum}

echo "comparing results and storing results in $Dir/diffs.log"

/code/trunk/swyx/bin/gtir_compare  $Dir/CSURF_FILES_DVT/$weird_code $exe_name $Dir/CSURF_FILES_DVT/$weird_code $exe_name -l $Dir/diffs.log -1 dvt -2 user_labels

echo "Diffs:"
cat $Dir/diffs.log
