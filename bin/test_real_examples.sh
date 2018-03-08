
dir="../real_world_examples/"
examples=(
    "grep-2.5.4 src/grep -lpcre"
    "gzip-1.2.4 gzip"
    "bar-1.11.0 bar"
    "conflict-6.0 conflict"
    "ed-0.2/ ed"
    "ed-0.9/ ed"
    "marst-2.4/ marst"
    "units-1.85/ units -lm -lreadline -lncurses"
    "doschk-1.1/ doschk"
    "bool-0.2/ src/bool"
    "m4-1.4.4/ src/m4"
    "patch-2.6.1/ src/patch"
    "enscript-1.6.1/ src/enscript -lm"
    "bison-2.1/ src/bison"
    "sed-4.2/ sed/sed"
    "flex-2.5.4/ flex"
    "make-3.80/ make"
    "tar-1.29/ src/tar"
);


compilers=("gcc"
	   "gcc8"
	   "clang");

optimizations=(""
	       "-O1"
	       "-O2"
	       "-O3"
	       "-Os");


for ((i = 0; i < ${#examples[@]}; i++)); do
    for compiler in "${compilers[@]}"; do
	export CC=$compiler
	for optimization in  "${optimizations[@]}"; do
	    export CFLAGS=$optimization
	    echo "#Example ${examples[$i]} with $compiler $optimization"
	    timeout 10m bash ./reassemble_and_test.sh $dir${examples[$i]}
	done
    done
done



#not even close
#"rsync-3.0.7/ rsync

#"lighttpd-1.4.18/ src/lighttpd -lpcre -ldl

#"re2c-0.13.5/ re2c g++
#"gperf-3.0.3/ src/gperf  g++
