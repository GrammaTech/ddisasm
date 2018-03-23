. /code/cgc-cbs/sourceme.sh
timeout=1000s

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

examples=(
    "CADET_00003"
    "CROMU_00001"
    "CROMU_00002"
    "CROMU_00003"
    "CROMU_00005"
    "CROMU_00007"
    "CROMU_00008"
    "CROMU_00010"
    "CROMU_00011"
    "CROMU_00012"
    "CROMU_00015"
    "CROMU_00018"
    "CROMU_00020"
    "CROMU_00021"
    "CROMU_00023"
    "CROMU_00024"
    "CROMU_00025"
    "CROMU_00026"
    "CROMU_00032"
  #  "CROMU_00033"
    "CROMU_00036"
    "CROMU_00037"
    "CROMU_00043"
  #  "CROMU_00044"
    "CROMU_00048"
  #  "CROMU_00055"
    "CROMU_00058"
  #  "CROMU_00061"
  #  "CROMU_00065" this one takes long
  #  "CROMU_00070"
  #  "CROMU_00077"
  #  "CROMU_00078" this one takes forever
  #  "CROMU_00094"
  #  "CROMU_00096" this one takes forever
    "CROMU_00097"
  #  "CROMU_00098"  this one takes forever
  #  "KPRCA_00001"
  #  "KPRCA_00002"
  #  "KPRCA_00003"
    "KPRCA_00007"
    "KPRCA_00008"
  #  "KPRCA_00009"
  #  "KPRCA_00012"
    "KPRCA_00013"
    "KPRCA_00014"
    "KPRCA_00015"
    "KPRCA_00017"
    "KPRCA_00018"
    "KPRCA_00020"
    "KPRCA_00021"
    "KPRCA_00022"
    "KPRCA_00023"
    "KPRCA_00027"
    "KPRCA_00028"
    "KPRCA_00030"
    "KPRCA_00031"
    "KPRCA_00032"
    "KPRCA_00033"
    "KPRCA_00034"
   # "KPRCA_00035"
    "KPRCA_00036"
    "KPRCA_00037"
   # "KPRCA_00040"
    "KPRCA_00041"
    "KPRCA_00042"
    "KPRCA_00043"
    "KPRCA_00045"
    "KPRCA_00046"
    "KPRCA_00051"
    "KPRCA_00052" 
    "KPRCA_00053"
    "KPRCA_00054"
  #  "KPRCA_00055"
  #  "KPRCA_00058"
    "KPRCA_00060"
  #  "KPRCA_00065"
  #  "KPRCA_00068"
  #  "KPRCA_00099"
  #  "KPRCA_00101"
  #  "KPRCA_00102"
    "KPRCA_00112"
    "NRFIN_00001"
    "NRFIN_00003"
    "NRFIN_00004"
    "NRFIN_00005"
    "NRFIN_00008"
  #  "NRFIN_00010"
    "NRFIN_00011"
  #  "NRFIN_00012"
    "NRFIN_00013"
  #  "NRFIN_00014"
    "NRFIN_00015"
  #  "NRFIN_00016"
    "NRFIN_00017"
 #   "NRFIN_00018"
 #   "NRFIN_00019"
    "NRFIN_00020"
    "NRFIN_00021"
    "NRFIN_00022"
    "NRFIN_00023"
    "NRFIN_00024"
    "NRFIN_00030"
 #   "NRFIN_00033"
    "NRFIN_00035"
 #   "NRFIN_00036"
    "NRFIN_00037"
 #   "NRFIN_00038"
    "NRFIN_00039"
    "NRFIN_00040"
    "NRFIN_00041"
    "NRFIN_00042"
  #  "NRFIN_00045"
  #  "NRFIN_00046"
    "NRFIN_00051"
  #  "NRFIN_00052" this one takes forever
    "NRFIN_00053"
    "NRFIN_00059"
    "NRFIN_00077"
  #  "TNETS_00002"
  #  "YAN01_00003"
    "YAN01_00007"
    "YAN01_00010"
    "YAN01_00011"
    "YAN01_00012"
    #  "YAN01_00016"

    "LUNGE_00002"
#    "NRFIN_00029"
#    "NRFIN_00034"
#    "KPRCA_00010"
   
);

dir="/code/cgc-cbs/cqe-challenges/"

strip=""
if [[ $# > 0 && $1 == "-strip" ]]; then
    strip="-strip"
    shift
fi

stir=""
if [[ $# > 0 && $1 == "-stir" ]]; then
    stir="-stir"
    shift
fi

for file in "${examples[@]}"; do
    if [ -d "$dir$file" ]; then
	for compiler in "${compilers[@]}"; do
	    for optimization in  "${optimizations[@]}"; do
		echo "#Example $file with $compiler $optimization"
		timeout $timeout bash ./CGC_reassemble_and_test.sh $strip $stir $dir$file $compiler $optimization
	    done
	done
    fi
done


dir="/code/cgc-cbs/examples/"

for file in "${examples[@]}"; do
    if [ -d "$dir$file" ]; then
	for compiler in "${compilers[@]}"; do
	    for optimization in  "${optimizations[@]}"; do
		echo "#Example $file with $compiler $optimization"
		timeout $timeout bash ./CGC_reassemble_and_test.sh $strip $stir $dir$file $compiler $optimization
	    done
	done
    fi
done



