
all: foo.s bar.s ex.c
	gcc -shared foo.s -o foo.so
	gcc -shared bar.s -o bar.so -L. -l:foo.so
	gcc ex.c -no-pie -o ex -L. -l:bar.so -l:foo.so
	LD_LIBRARY_PATH=. ./ex > out.txt
clean:
	rm -f ex foo.so bar.so out.txt
check:
	LD_LIBRARY_PATH=. ./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
