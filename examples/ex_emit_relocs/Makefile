CC="gcc"
CFLAGS=
EXEC=

all: ex.c bar.c
	#$(CC) ex.c bar.o -o ex -fno-pie -no-pie -Wl,--emit-relocs
	$(CC) -c bar.c $(CFLAGS) -o bar.o -fpie -pie
	$(CC) -c ex.c $(CFLAGS) -o ex.o -fno-pie -no-pie
	$(CC) ex.o bar.o $(CFLAGS) -o ex -no-pie -Wl,--emit-relocs
	@ $(EXEC) ./ex > out.txt
#bar.o: bar.c
#	$(CC) -c bar.c $(CFLAGS) -fpie -pie -o bar.o
clean:
	rm -f ex ex.unstripped out.txt *.s *.lib *.exp *.o *.err
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
