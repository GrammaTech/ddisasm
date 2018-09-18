
all:
	make all -C ./src

doc:
	make all -C ./doc

check: all
	make check -C ./tests

check-slow: all
	make check-slow -C ./tests

clean:
	make clean -C ./src
	make clean -C ./examples
	make clean -C ./doc

