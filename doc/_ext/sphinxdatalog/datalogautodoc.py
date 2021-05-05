from __future__ import unicode_literals

import os
import re
import docutils
import itertools

import sphinx.addnodes
from docutils import nodes
from docutils.parsers.rst import Directive


def trailing_comment(string):
    lines = string.splitlines()
    lines.reverse()
    c_lines = list(itertools.takewhile(lambda s: s[0:3] == "// ", lines))
    c_lines.reverse()
    return "\n".join(list(map(lambda s: s[3:], c_lines)))


# See https://www.sphinx-doc.org/en/master/extdev/nodes.html for the
# descriptions of the Sphinx nodes available to build documentation.
class DatalogParser:

    # Parse the source file (simply with a regex) and pack the results
    # into a Sphinx `desc` node with a `desc_signature` and
    # `desc_content` for the docstring.
    def parsefile(self, sourcepath):
        sourcepath = os.path.realpath(sourcepath)
        if not os.path.exists(sourcepath):
            raise ValueError("Can't find file: " + sourcepath)

        main = sphinx.addnodes.desc()
        index = 0
        # Split into [stuff, name, params, stuff2, name2, params2, ...]
        groups = re.split("(.*)\\((.*)\\):-", open(sourcepath).read())
        while ((index + 1) * 3) < len(groups):
            name = groups[(index * 3) + 1]
            params = sphinx.addnodes.desc_parameterlist("", "")
            for param in re.split(",", groups[(index * 3) + 2]):
                params += sphinx.addnodes.desc_parameter("", param)
            sig = sphinx.addnodes.desc_signature("", "")
            sig += sphinx.addnodes.desc_name("", name)
            sig += params
            content = sphinx.addnodes.desc_content()
            content += nodes.paragraph(
                text=trailing_comment(groups[index * 3])
            )
            main += sig
            main += content
            index = index + 1

        return main


class NodeWalker:
    def __init__(self, scope, document, callback):
        self.scope = scope
        self.document = document
        self.callback = callback

    def dispatch_visit(self, node):
        pass

    def dispatch_departure(self, node):
        pass


def walk_tree(node, callback, scope):
    document = docutils.utils.new_document("")
    walker = NodeWalker(scope, document, callback)
    node.walkabout(walker)


class AutoDirective(Directive):
    has_content = False
    required_arguments = 2
    optional_arguments = 0
    final_argument_whitespace = False

    def run(self):
        if ":" in self.name:
            self.domain, self.objtype = self.name.split(":", 1)
        else:
            self.domain, self.objtype = "", self.name
        self.objtype = self.objtype[len("auto") :]
        self.env = self.state.document.settings.env
        sourcedir = self.env.app.config.datalogautodoc_basedir
        self.sourcepath = os.path.join(sourcedir, self.arguments[0])
        self.matches = []

        # Load all datalog objects from file
        file_relations = self.env.datalogparser.parsefile(self.sourcepath)
        # Store nodes matching the search pattern in self.matches
        self.filter(file_relations)
        if len(self.matches) == 0:
            args = self.arguments
            raise ValueError(
                'No matches for directive "{}" in '
                ' file "{}" with arguments {}'.format(
                    self.objtype, args[0], str(args[1:])
                )
            )

        scope = self.env.ref_context.get("dl:scope", [])
        for node in self.matches:
            # Set ids and register nodes in global index
            walk_tree(node, self.register, scope)

        self.state.document.settings.record_dependencies.add(self.sourcepath)

        return self.matches

    def filter(self, file_relations):
        walk_tree(file_relations, self.match, scope=[])

    def register(self, node, scope):
        objtype = type(node).__name__.lower()
        node["ids"] = [node.uid(scope)]
        dictionary = self.env.domaindata["dl"][objtype]
        node.register(self.env.docname, scope, dictionary)


class AutoFileDirective(AutoDirective):
    required_arguments = 1

    def filter(self, file_relations):
        # Take all elements of file
        for node in file_relations:
            self.matches.append(node)


class AutoRelationDirective(AutoDirective):
    final_argument_whitespace = True


class AutoType(AutoDirective):
    pass


def update_builder(app):
    app.env.datalogparser = DatalogParser()


def setup(app):
    # Config values
    app.add_config_value("datalogautodoc_basedir", "..", "html")

    # Directives
    app.add_directive("dl:autofile", AutoFileDirective)
    app.add_directive("dl:autorelation", AutoRelationDirective)
    app.add_directive("dl:autotype", AutoType)

    app.connect("builder-inited", update_builder)
