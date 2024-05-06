CC=gcc
AR=ar
CFLAGS=
EXEC=

ifeq ($(CC),arm-linux-gnueabihf-gcc)
	LIB_ASM_SRC=foo_arm32.s
endif
ifeq ($(CC),aarch64-linux-gnu-gcc)
	LIB_ASM_SRC=foo_arm64.s
endif
ifeq ($(CC),gcc)
ifneq (,(findstring -m32,$(CFLAGS)))
	LIB_ASM_SRC=foo_x64.s
else
	LIB_ASM_SRC=foo_x86.s
endif
endif

LIB_SRC=bar.c
LIB_OBJ=$(patsubst %.c, %.o, $(LIB_SRC))
LIB_ASM_OBJ=$(patsubst %.s, %.o, $(LIB_ASM_SRC))

LIB_ASM_OBJ_ALL=foo_arm32.o foo_arm64.o foo_x64.o

.PHONY: all check clean

all: out.txt

out.txt: ex
	@ $(EXEC) ./ex > $@

ex: ex.o libtest.a
	$(CC) $(CFLAGS) -o $@ $^

libtest.a: $(LIB_OBJ) $(LIB_ASM_OBJ)
	$(AR) -rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(LIB_ASM_OBJ): $(LIB_ASM_SRC)
	$(CC) -c -o $@ $^

clean:
	rm -f ex out.txt libtest.a ex.o $(LIB_OBJ) $(LIB_ASM_OBJ_ALL)
	rm -fr ex.unstripped libtest-tmp libtest.gtirb

check: ex
	@ $(EXEC) ./ex >/tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
