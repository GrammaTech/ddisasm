CC="gcc"
CFLAGS=


all: ex.c 
	$(CC) ex.c  $(CFLAGS) -o ex
	@ echo "A" |./ex > out.txt
	@ echo "B" |./ex >> out.txt
	@ echo "C" |./ex >> out.txt
clean:
	rm -f ex out.txt
	rm -fr *.s *.old*  dl_files
check:
	@ echo "A" |./ex > /tmp/res.txt
	@ echo "B" |./ex >> /tmp/res.txt
	@ echo "C" |./ex >> /tmp/res.txt
	@ bash ./test.sh


