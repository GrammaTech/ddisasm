
dir="/code/cgc-cbs/cqe-challenges/"
examples=(
    "CROMU_00001 -lm"
    "CROMU_00002 -lm"
    "CROMU_00003 -lm"
    "CROMU_00004 -lm" #some tests fail in the original 
    "CROMU_00005 -lm"
    #6 does not compile
    #7 does not exist
    "CROMU_00008 -lm"
    "CROMU_00009 -lm" #all tests fail in the original
    "CROMU_00010 -lm"
    "CROMU_00011 -lm"
    "CROMU_00012 -lm" #some tests fail in the original
    "CROMU_00014 -lm" #all tests fail in the original
    "CROMU_00015 -lm"
    "CROMU_00016 -lm" #all tests fail in the original
    #"CROMU_00017 -lm" #no test for release
    "CROMU_00018 -lm"
    #"CROMU_00019 -lm" #no test for release
    #"CROMU_00020 -lm" #no test for release
    #"CROMU_00021 -lm" #no test for release
    "CROMU_00022 -lm" #all tests fail in the original
    #"CROMU_00023 -lm" here there is a problem
    "CROMU_00024 -lm" #some tests fail in the original
    "CROMU_00025 -lm"
    "CROMU_00026 -lm" #some tests fail in the original
    #"CROMU_00027 -lm" here there is a problem (non-termination)
    "CROMU_00028 -lm" #all tests fail in the original
    "CROMU_00029 -lm" #all tests fail in the original
    # "CROMU_00030 -lm" #no tests for release
    # "CROMU_00031 -lm" #all tests fail in the original
);

for ((i = 0; i < ${#examples[@]}; i++)); do
    ./CBC_reassemble_and_test.sh $dir${examples[$i]}
done
	       
