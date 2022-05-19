.PHONY: all clean check
all: out.txt

out.txt: ex
	@./$^ > $@
ex: src.s
	gcc $^ -no-pie -g -o $@

clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old*  dl_files *.gtirb
check:
	./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
