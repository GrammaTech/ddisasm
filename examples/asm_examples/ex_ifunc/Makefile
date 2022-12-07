
all: ex_original.s
	gcc -shared -Wl,--version-script=ex.map ex_original.s -o ex.so
clean:
	rm -f ex.so ex.gtirb out.txt
