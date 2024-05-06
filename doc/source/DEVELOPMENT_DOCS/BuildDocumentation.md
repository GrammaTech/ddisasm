Building the documentation
===================================


Ddisasm's documentation uses [Sphinx](https://www.sphinx-doc.org/en/master/) and [souffle](https://souffle-lang.github.io/)
(souffle is used to analyze the Datalog dependency graph).

If you are building Ddisasm from source, you will need to [build souffle with 64 bit support](https://github.com/GrammaTech/ddisasm#dependencies).
If you only need Souffle for the documentation, you can install the off-the-shelf package
(see [Souffle installation instructions](https://souffle-lang.github.io/install)).

Once you have installed souffle, you can run the following commands to build the html documentation:

```
cd doc
pip3 install -r requirements-docs.txt
make
```

This will go to the documentation directory, install sphinx and a few extensions,
and build the html documentation in `doc/build`.
You can use `make help` to list other documentation options:

```bash
$ make help
Sphinx v6.1.3
Please use 'make target' where target is one of
  html        to make standalone HTML files
  dirhtml     to make HTML files named index.html in directories
  singlehtml  to make a single large HTML file
  pickle      to make pickle files
  json        to make JSON files
  htmlhelp    to make HTML files and an HTML help project
  qthelp      to make HTML files and a qthelp project
  devhelp     to make HTML files and a Devhelp project
  epub        to make an epub
  latex       to make LaTeX files, you can set PAPER=a4 or PAPER=letter
  latexpdf    to make LaTeX and PDF files (default pdflatex)
  latexpdfja  to make LaTeX files and run them through platex/dvipdfmx
  text        to make text files
  man         to make manual pages
  texinfo     to make Texinfo files
  info        to make Texinfo files and run them through makeinfo
  gettext     to make PO message catalogs
  changes     to make an overview of all changed/added/deprecated items
  xml         to make Docutils-native XML files
  pseudoxml   to make pseudoxml-XML files for display purposes
  linkcheck   to check all external links for integrity
  doctest     to run all doctests embedded in the documentation (if enabled)
  coverage    to run coverage check of the documentation (if enabled)
  clean       to remove everything in the build directory
```
