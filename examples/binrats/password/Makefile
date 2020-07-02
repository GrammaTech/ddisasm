
all: password.c
	aarch64-linux-gnu-gcc password.c -o password
	@ echo "foo" \
    | qemu-aarch64 -L /usr/aarch64-linux-gnu password \
    > out.txt
	@ echo "admin\n4dm1n__4eva" \
    | qemu-aarch64 -L /usr/aarch64-linux-gnu password \
    >> out.txt
clean:
	rm -f password out.txt
check:
	@ echo "foo" \
    | qemu-aarch64 -L /usr/aarch64-linux-gnu password \
    > /tmp/res.txt
	@ echo "admin\n4dm1n__4eva" \
    | qemu-aarch64 -L /usr/aarch64-linux-gnu password \
    >> /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK

