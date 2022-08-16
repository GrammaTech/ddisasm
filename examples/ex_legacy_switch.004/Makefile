CC="gcc"
CFLAGS=
EXEC=

SEQUENCE = 002 003 004 005 006 007 008 009 010 011 012 013 014 015 016 017 018 019 020 902 903 904 905 906 907 908 909 910 911 912 913 914 915 916 917 918 919 920 602 603 604 605 606 607 608 609 610 611 612 613 614 615 616 617 618 619 620

all: ex.c
	$(CC) ex.c $(CFLAGS) -o ex
	@ for CHAR in $(SEQUENCE); do $(EXEC) ./ex.exe "$$CHAR"; done > out.txt
clean:
	rm -f ex.exe *.txt *.s *.lib *.exp *.o *.err
check:
	@ for CHAR in $(SEQUENCE); do $(EXEC) ./ex.exe "$$CHAR"; done > check.txt
	@ diff out.txt check.txt && echo TEST OK
