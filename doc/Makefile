all: ddisasm.html ddisasm.1.gz

clean:
	rm -f *.html *.gz

%.html: %.md
	pandoc -s -t html $< -o $@

%.md.tmp: %.md
	pandoc -s -t man $< -o $@

%.1.gz: %.md.tmp
	gzip -9 < $< > $@
