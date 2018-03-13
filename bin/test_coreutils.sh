dir_make="../coreutils-8.21/"
dir="../coreutils-8.21/src"
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

compilers=("gcc"
	  "gcc8"
	  "clang"
	  );

optimizations=(""
	      "-O1"
	      "-O2"
	      "-O3"
	      "-Os"
	      );



for compiler in "${compilers[@]}"; do
    export CC=$compiler
    for optimization in  "${optimizations[@]}"; do
	export CFLAGS=$optimization
	printf "# Cleaning and Rebuilding coreutils with $compiler $optimization\n"
	if !( make clean -e -C $dir_make &>/dev/null  && make -e -C $dir_make &>/dev/null); then
	    printf "# ${red}Initial compilation failed${normal}\n"
	    
	else 
	    for ((i = 0; i < ${#examples[@]}; i++)); do
		echo "#Example ${examples[$i]}"
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
done



#not even close

#"lighttpd-1.4.18/ src/lighttpd -lpcre -ldl



#with .init_array
#"re2c-0.13.5/ re2c g++
