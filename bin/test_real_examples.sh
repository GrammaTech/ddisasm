
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
    "rsync-3.0.7/ rsync"
    "gperf-3.0.3/ src/gperf  g++"
    "re2c-0.13.5/ re2c g++"
    "tar-1.29/ src/tar"
    "lighttpd-1.4.18/ src/lighttpd -rdynamic -lpcre -ldl"
);

compilers=(
    "gcc"
    "gcc8"
    "clang"
);

cpp_compilers=(
    "g++"
    "g++8"
    "clang++"
);

optimizations=(
    ""
    "-O1"
    "-O2"
    "-O3"
    "-Os"
);


for ((i = 0; i < ${#examples[@]}; i++)); do
    j=0
    for compiler in "${compilers[@]}"; do
	export CC=$compiler
	export CXX=${cpp_compilers[$j]}
	for optimization in  "${optimizations[@]}"; do
	    export CFLAGS=$optimization
	    echo "#Example ${examples[$i]} with $CC/$CXX $optimization"
	    timeout 10m bash ./reassemble_and_test.sh $dir${examples[$i]}
	done
    j=$j+1	
    done
done


