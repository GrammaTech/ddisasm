import os
import sys

sys.path.append(os.path.abspath("./_ext"))

extensions = [
    "recommonmark",
    "sphinx_markdown_tables",
    "sphinxdatalog.datalogdomain",
    "sphinx_rtd_theme",
]

project = "Ddisasm"
todo_include_todos = True
primary_domain = "dl"
default_role = "pred"
html_title = "Ddisasm documentation"
html_short_title = "Ddisasm docs"

html_theme = "sphinx_rtd_theme"
