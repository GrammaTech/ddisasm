
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


strip --strip-unneeded -o $dir/$exe.stripped $dir/$exe
exename=$exename.stripped

echo "Calling the disassembler on $dir/$exe.stripped and storing the result in $dir/result "
./disasm $dir/$exe.stripped -debug -function_hints > $dir/$exe.s


cd $dir/$exedir

echo "Melting"
/code/trunk/gtx/bin/gtm --ir_path ./CSURF_FILES  --targets $exename
echo "Getting functions"
/code/trunk/csurf/bin/csurf -nogui $exename.prj <../../bin/get_functions.stk | cut -d ' ' -f 2 | sort > /tmp/swyx_functions.txt


echo "Comparing functions and storing the results in $dir/diffs.diff"

diff /tmp/swyx_functions.txt datalog_disasm_functions.txt > diff.diff
