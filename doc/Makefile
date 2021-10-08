all: ddisasm.html ddisasm.1.gz

datalog-docs:
	python3  build_index.py
	python3 -m sphinx  . datalog-docs
clean:
	rm -f *.html *.gz

%.html: %.md
	pandoc -s -t html $< -o $@

%.md.tmp: %.md
	pandoc -s -t man $< -o $@

%.1.gz: %.md.tmp
	gzip -9 < $< > $@
