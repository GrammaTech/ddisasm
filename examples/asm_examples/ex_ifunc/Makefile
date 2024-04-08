CC="gcc"
CFLAGS=

all: ex_original.s
	$(CC) -shared -Wl,--version-script=ex.map $(CFLAGS) ex_original.s -o ex.so
clean:
	rm -f ex.so ex.gtirb out.txt
