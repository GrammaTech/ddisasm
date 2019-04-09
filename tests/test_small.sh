dir="../examples/"

compilers=("gcc"
	   "clang");

cpp_compilers=(
    "g++"
    "clang++"
);

optimizations=(""
	       "-O1"
	       "-O2"
	       "-O3"
	       "-Os"
	      );

examples=(
    "ex1 ex"
    "ex_2modulesPIC ex"
    "ex_confusing_data ex"
    "ex_float ex"
    "ex_fprintf ex"
    "ex_getoptlong ex"
    "ex_memberPointer ex g++"
    "ex_noreturn ex"
    "ex_pointerReatribution ex"
    "ex_pointerReatribution2 ex"
    "ex_pointerReatribution3 ex"
    "ex_stat ex"
    "ex_struct ex"
    "ex_switch ex"
    "ex_unitialized_data ex"
    "ex_virtualDispatch ex g++"
    "ex_false_pointer_array ex"
);

strip=""
if [[ $# > 0 && $1 == "-strip" ]]; then
    strip="-strip"
    shift
fi

error=0
success=0
for ((i = 0; i < ${#examples[@]}; i++)); do
    j=0
    for compiler in "${compilers[@]}"; do
	export CC=$compiler
	export CXX=${cpp_compilers[$j]}
	for optimization in  "${optimizations[@]}"; do
	    export CFLAGS=$optimization
	    echo "#Example $file with $compiler $optimization"
        if !(./reassemble_and_test.sh $strip -stir $dir${examples[$i]}) then
	       ((error++))
	       else
		   ((success++))
	    fi
	done
	((j++))  
    done
done

echo "$success/$((error+success)) tests succeed"

if (( $error > 0 )); then 
    echo "$error tests failed"
    exit 1
fi
