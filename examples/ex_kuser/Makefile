CC=
CFLAGS=
EXEC=

all:
	$(CC) ex.c -o ex
	@ $(EXEC) ./ex > out.txt
clean:
	rm -f ex *.exe *.dll out.txt *.s *.lib *.exp *.o *.err
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
