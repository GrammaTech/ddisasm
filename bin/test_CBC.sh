
dir="/code/cgc-cbs/cqe-challenges/"
examples=("CROMU_00001 -lm"
	  "CROMU_00002 -lm"
	  "CROMU_00003 -lm"
	  "CROMU_00004 -lm"
	  "CROMU_00005 -lm"
	  "CROMU_00008 -lm"




	 );

for ((i = 0; i < ${#examples[@]}; i++)); do
    ./CBC_reassemble_and_test.sh $dir${examples[$i]}
done
	       
