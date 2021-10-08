import os
import sys

sys.path.append(os.path.abspath("./_ext"))

extensions = ["sphinxdatalog.datalogdomain"]

project = "Ddisasm"
todo_include_todos = True
primary_domain = "dl"
default_role = "pred"
html_title = "Ddisasm datalog documentation"
html_short_title = "Ddisasm docs"
html_theme = "alabaster"
html_theme_options = {"description": "Ddisasm's datalog internal API"}
