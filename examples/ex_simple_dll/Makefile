CC=
CFLAGS=
EXEC=

all: dll
	$(CC) ex.c test.dll -o ex
	@ $(EXEC) ./ex > out.txt
dll: test.h test.c
	$(CC) test.c $(CFLAGS) -shared -o test.dll
clean:
	rm -f ex *.dll out.txt *.s *.lib *.exp *.o *.err
check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
