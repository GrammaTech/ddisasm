. /code/cgc-cbs/sourceme.sh
timeout=500s

optimizations=(""
	       "-O1"
	       "-O2"
	       "-O3"
	       "-Os");

compilers=("gcc"
	   "gcc8"
	   "clang");

optimizations=(""
	       "-O1"
	       "-O2"
	       "-O3"
	       "-Os");

dir="/code/cgc-cbs/examples/"

for file in $dir/* ; do
    for compiler in "${compilers[@]}"; do
	for optimization in  "${optimizations[@]}"; do
	      echo "#Example $file with $compiler $optimization"
	    timeout $timeout ./CGC_reassemble_and_test.sh $file $compiler $optimization
	done
    done
done

dir="/code/cgc-cbs/cqe-challenges/"

for file in $dir/* ; do
    for compiler in "${compilers[@]}"; do
	for optimization in  "${optimizations[@]}"; do
	    echo "#Example $file with $compiler $optimization"
	    timeout $timeout ./CGC_reassemble_and_test.sh $file $compiler $optimization
	done
    done

done



