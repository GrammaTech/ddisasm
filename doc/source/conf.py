import os
import sys
import sphinx_adc_theme

sys.path.append(os.path.abspath("./_ext"))

extensions = [
    "recommonmark",
    "sphinx_markdown_tables",
    "sphinxdatalog.datalogdomain",
]

project = "Ddisasm"
todo_include_todos = True
primary_domain = "dl"
default_role = "pred"
html_title = "Ddisasm documentation"
html_short_title = "Ddisasm docs"

html_theme = "sphinx_adc_theme"
html_theme_path = [sphinx_adc_theme.get_html_theme_path()]
