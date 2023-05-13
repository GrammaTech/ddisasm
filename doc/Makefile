SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

%: Makefile
	python3  build_index.py
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	pandoc -s -t man "$(SOURCEDIR)/MANUAL/ddisasm.rst" -o ddisasm.md
	

all: ddisasm.html ddisasm.1.gz

datalog-docs:
	python3  build_index.py
	python3 -m sphinx "$(SOURCEDIR)" "$(BUILDDIR)"

clean:
	rm -f *.html *.gz

%.html: %.md
	pandoc -s -t html $< -o $@

%.md.tmp: %.md
	pandoc -s -t man $< -o $@

%.1.gz: %.md.tmp
	gzip -9 < $< > $@
