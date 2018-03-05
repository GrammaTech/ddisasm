. /code/cgc-cbs/sourceme.sh

examples=(
    "CROMU_00001"
    "CROMU_00002"
    "CROMU_00003"
    "CROMU_00004" #some tests fail in the original 
    "CROMU_00005"
    #6 does not compile
    #7 does not exist
    "CROMU_00008"
    #"CROMU_00009" #all tests fail in the original
    "CROMU_00010"
    "CROMU_00011"
    "CROMU_00012" #some tests fail in the original
    #"CROMU_00014" #all tests fail in the original
    "CROMU_00015"
    #problems with clang and -O1
    
    #"CROMU_00016" #all tests fail in the original
    #"CROMU_00017" #no test for release
    "CROMU_00018"
    #"CROMU_00019" #no test for release
    #"CROMU_00020" #no test for release
    #"CROMU_00021" #no test for release
    #"CROMU_00022" #all tests fail in the original
    "CROMU_00023"
    "CROMU_00024" #some tests fail in the original
    "CROMU_00025"
    # problems with clang

    
    "CROMU_00026" #some tests fail in the original
    "CROMU_00027" 
    #"CROMU_00028" #all tests fail in the original
    #"CROMU_00029" #all tests fail in the original
    # "CROMU_00030" #no tests for release
    # "CROMU_00031" #all tests fail in the original
    "CROMU_00032" #some
    # "CROMU_00033" #all tests fail in the original
    # "CROMU_00034" #no tests for release
    # "CROMU_00035" #all tests fail in the original
    "CROMU_00036"
    "CROMU_00037"
    "CROMU_00038" #some tests fail in the original
    "CROMU_00039" #some tests fail in the original
    #"CROMU_00040 #all tests fail in the original
    #"CROMU_00041 # no tests for release
    #"CROMU_00042 #all tests fail in the original
    #"CROMU_00043 # no tests for release
    #"CROMU_00044 #all tests fail in the original

    "KPRCA_00002" #some tests fail in the original
    "KPRCA_00007" #some tests fail in the original
    "KPRCA_00008"
    #"KPRCA_00009" #possible non termination
    #"KPRCA_00010" #takes long
    "KPRCA_00011"
    "KPRCA_00012" #some tests fail in the original
);

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
	    ./CGC_reassemble_and_test.sh $file $compiler $optimization
	done
    done
done

dir="/code/cgc-cbs/cqe-challenges/"

for file in $dir/* ; do
    for compiler in "${compilers[@]}"; do
	for optimization in  "${optimizations[@]}"; do
	    ./CGC_reassemble_and_test.sh $file $compiler $optimization
	done
    done

done



