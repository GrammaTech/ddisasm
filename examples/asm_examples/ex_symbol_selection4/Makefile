CC=g++
CFLAGS=

all: ex

ex: ex_original.s
	$(CC) -no-pie -Wl,-T,linker-script.ld ex_original.s $(CFLAGS) -o $@
	@./ex > out.txt
clean:
	rm -f ex out.txt
check:
	@./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
