
all:
	make all -C ./src

check: all
	make check -C ./tests


clean:
	make clean -C ./src
	make clean -C ./examples

