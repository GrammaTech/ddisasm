
dir="/code/cgc-cbs/cqe-challenges/"
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
    "CROMU_00026" #some tests fail in the original
    "CROMU_00027" #here there is a problem (non-termination)
    #"CROMU_00028" #all tests fail in the original
    #"CROMU_00029" #all tests fail in the original
    # "CROMU_00030" #no tests for release
    # "CROMU_00031" #all tests fail in the original
);

for ((i = 0; i < ${#examples[@]}; i++)); do
    ./CBC_reassemble_and_test.sh $dir${examples[$i]}
    ./CBC_reassemble_and_test.sh $dir${examples[$i]} -O1
    ./CBC_reassemble_and_test.sh $dir${examples[$i]} -O2
    ./CBC_reassemble_and_test.sh $dir${examples[$i]} -O3
    
done
