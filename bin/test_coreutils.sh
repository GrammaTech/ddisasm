
dir_make="../coreutils-8.21"
if [[ $# -eq 1 && $1 != "-h" && $1 != "--help" ]]; then
 dir_make=$1
fi

if [[ ! -d $dir_make ]]; then
    printf "Coreutils not found in $dir_make\n"
    dir_make="not_found"
fi
    

if [[ ($# > 0 && ($1 == "-h" || $1 == "--help")) || $dir_make == "not_found" ]]; then
    printf "USAGE: ./test_coreutils.sh Coreutils_path
 This script receives the path where the coreutils directory is located and
- rebuilds coreutils with different compilers and optimization options
- rewrite the binaries
- run the coreutils tests
"   
    exit

fi



dir="$dir_make/src"
examples=(
    "[ "
    "base64"
    "basename"
    "cat"
    "chcon"
    "chgrp"
    "chmod"
    "chown"
    "chroot"
    "cksum"
    "comm"
    "cp"
    "csplit"
    "cut"
    "date"
    "dd"
    "df"
    "dir"
    "dircolors"
    "dirname"
    "du"
    "echo"
    "env"
    "expand"
    "expr -lgmp"
    "factor -lgmp"
    "false"
    "fmt"
    "fold"
    "getlimits"
    "ginstall" 
    "groups"
    "head"
    "hostid"
    "id"
    "join"
    "kill"
    "link"
    "ln"
    "logname"
    "ls"
    "make-prime-list"
    "md5sum"
    "mkdir"
    "mkfifo"
    "mknod"
    "mktemp"
    "mv"
    "nice"
    "nl"
    "nohup"
    "nproc"
    "numfmt"
    "od"
    "paste"
    "pathchk"
    "pinky"
    "pr"
    "printenv"
    "printf"
    "ptx"
    "pwd"
    "readlink"
    "realpath"
    "rm"
    "rmdir"
    "runcon"
    "seq"
    "setuidgid"
    "sha1sum"
    "sha224sum"
    "sha256sum"
    "sha384sum"
    "sha512sum"
    "shred"
    "shuf"
    "sleep"
    "sort -pthread"
    "split"
    "stat"
    "stdbuf"
    "stty"
    "sum"
    "sync"
    "tac"
    "tail"
    "tee"
    "test"
    "timeout -lrt"
    "touch"
    "tr"
    "true"
    "truncate"
    "tsort"
    "tty"
    "uname"
    "unexpand"
    "uniq"
    "unlink"
    "uptime"
    "users"
    "vdir"
    "wc"
    "who"
    "whoami"
    "yes"
);

compilers=(
    "gcc"
    "gcc8"
    "clang"
);

optimizations=(
    ""
    "-O1"
    "-O2"
    "-O3"
    "-Os"
);



for compiler in "${compilers[@]}"; do
    if [[ -x $(command -v $compiler) ]]; then 
	export CC=$compiler
	for optimization in  "${optimizations[@]}"; do
	    export CFLAGS=$optimization
	    printf "# Cleaning and Rebuilding coreutils with $compiler $optimization\n"
	    if !( make clean -e -C $dir_make &>/dev/null  && make -e -C $dir_make &>/dev/null); then
		printf "# ${red}Initial compilation failed${normal}\n"
		
	    else
		
		for ((i = 0; i < ${#examples[@]}; i++)); do
		    echo "#Example ${examples[$i]}"
		    exe_name=(${examples[$i]})
	            echo "Stripping ${exe_name[0]}"
		    cp "$dir/${exe_name[0]}" "$dir/${exe_name[0]}.unstripped"
		    strip --strip-unneeded $dir/${exe_name[0]}
		    timeout 10m bash ./reassemble_no_rebuild.sh $dir ${examples[$i]}
		done
		
		printf "# Testing\n"
		#export RUN_EXPENSIVE_TESTS=yes
		#export RUN_VERY_EXPENSIVE_TESTS=yes
		if !(make check -C $dir_make); then
		    printf "# ${red}Testing FAILED ${normal}\n\n"
		else
		    printf "# ${green}Testing SUCCEED ${normal}\n\n"
		fi
	    fi
	done
    else
	printf "#Compiler $compiler not found\n"
    fi
done
