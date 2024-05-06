.PHONY: all clean check
all: out.txt

out.txt: ex
	@./$^ > $@
ex: src.s
	gcc $^ -pie -m32 -o $@

clean:
	rm -f ex out.txt
check:
	./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
