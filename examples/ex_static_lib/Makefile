CC=gcc
AR=ar
CFLAGS=
EXEC=

LIBMSG_SRC=msg_one.c msg_two.c msg_three.c msg_four.c
LIBMSG_OBJ=$(patsubst %.c, %.o, $(LIBMSG_SRC))

.PHONY: all check clean

all: out.txt

out.txt: ex
	@ $(EXEC) ./ex > $@

ex: ex.o libmsg.a
	$(CC) $(CFLAGS) -o $@ $^

libmsg.a: $(LIBMSG_OBJ)
	$(AR) -rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f ex out.txt libmsg.a ex.o $(LIBMSG_OBJ)
	rm -fr ex.unstripped *.s libmsg-tmp

check:
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
