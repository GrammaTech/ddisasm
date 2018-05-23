
all: ex_original.s
    gcc ex_original.s  -o ex
    ./ex > out.txt
clean:
    rm -f ex out.txt
    rm -fr ex.s *.old*  dl_files
check:
    ./ex > /tmp/res.txt
    @ bash ./test.sh
