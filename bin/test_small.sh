compilers=("gcc"
	   "gcc8"
	   "clang");

optimizations=(""
	       "-O1"
	       "-O2"
	       "-O3"
	       "-Os");

for file in ../examples/ex_* ; do

    for compiler in "${compilers[@]}"; do
	export CC=$compiler
	for optimization in  "${optimizations[@]}"; do
	    export CFLAGS=$optimization
	    echo "#Example $file with $compiler $optimization"
	    ./reassemble_and_test.sh $file ex
	done
    done
done
