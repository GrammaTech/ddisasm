from collections import defaultdict
from typing import Tuple, Optional, List
import re
import sphinx.addnodes
from docutils import nodes
from docutils.parsers.rst import Directive
from sphinx.domains import Domain, Index
from docutils.parsers.rst import directives
from sphinx.roles import XRefRole
from sphinx.directives import ObjectDescription
from sphinx.util import logging
from sphinx.util.nodes import make_refnode
from sphinx import addnodes
from docutils.statemachine import ViewList
from sphinx.domains.std import StandardDomain
from pathlib import Path
import networkx as nx

THIS_DIRECTORY = Path(__file__).resolve().parent

MAIN_DIRECTORY = THIS_DIRECTORY.parent.parent.parent

# Dictionaries with dependencies between
# predicates computed by souffle
DEPENDENCE_GRAPH = defaultdict(list)
DEPENDENCE_GRAPH_INV = defaultdict(list)

SCC_GRAPH: nx.Graph = None

logger = logging.getLogger(__name__)


def split_component(node: str) -> Tuple[str, str]:
    """
    Split the component name from a predicate
    name. If the predicate is not in a component
    the component part will be empty.
    """
    comp_index = node.rfind(".")
    if comp_index != -1:
        return node[0 : comp_index + 1], node[comp_index + 1 :]
    return "", node


class PredicateNode(ObjectDescription):
    """A custom node that describes a datalog predicate"""

    required_arguments = 1

    option_spec = {"contains": directives.unchanged_required}

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name(text=sig)
        signode += addnodes.desc_type(text="Predicate")
        return sig

    def add_target_and_index(self, name_cls, sig, signode):
        signode["ids"].append("pred" + "-" + sig)
        name = "{}.{}.{}".format("dl", type(self).__name__, sig)
        objs = self.env.domaindata["dl"]["objects"]
        objs.append(
            (name, sig, "Predicate", self.env.docname, "pred" + "-" + sig, 0)
        )


class PredicateIndex(Index):
    """
    An index of predicates
    """

    name = "pred_idx"
    localname = "Predicate Index"
    shortname = "PredicateIndex"

    def __init__(self, *args, **kwargs):
        super(PredicateIndex, self).__init__(*args, **kwargs)

    def generate(self):
        """
        Generate the index of predicates
        """
        content = {}
        items = (
            (name, dname, typ, doc, anchor)
            for name, dname, typ, doc, anchor, pr in self.domain.get_objects()
        )
        items = sorted(items, key=lambda item: item[0])
        for name, dispname, typ, docname, anchor in items:
            lis = content.setdefault("PredicateIndex", [])
            lis.append((dispname, 0, docname, anchor, docname, "", typ))
        re = [(k, v) for k, v in sorted(content.items())]

        return (re, True)


class DatalogDomain(Domain):
    """
    A domain for datalog, it contains
    predicates and a predicate index.
    It specifies how to resolve references.
    """

    name = "dl"
    label = "Datalog"

    roles = {
        "pred": XRefRole(),
        "recpred": XRefRole(innernodeclass=nodes.emphasis),
    }

    directives = {
        "pred": PredicateNode,
    }

    indices = {PredicateIndex}

    initial_data = {
        "objects": [],
    }

    def get_full_qualified_name(self, node):
        return f"dl.{type(node).__name__}.{node.arguments[0]}"

    def get_objects(self):
        for obj in self.data["objects"]:
            yield (obj)

    def resolve_xref(
        self, env, fromdocname, builder, typ, target, node, contnode
    ):

        match = [
            (docname, anchor)
            for name, dispname, ty, docname, anchor, pr in self.get_objects()
            if dispname == target
        ]

        if len(match) > 0:
            todocname = match[0][0]
            targ = match[0][1]

            return make_refnode(
                builder, fromdocname, todocname, targ, contnode, targ
            )
        else:
            return None


class AutoFileDirective(Directive):
    """
    Directive to process a datalog source file.
    """

    has_content = True
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = False

    def _parse_predicate_fields(
        self, fields: str
    ) -> sphinx.addnodes.desc_parameterlist:
        """
        Parse the fileds of the predicate and add them
        to the description.
        """
        params = sphinx.addnodes.desc_parameterlist("", "")
        for field in re.split(",", fields):
            params += sphinx.addnodes.desc_parameter("", field.strip())
        return params

    def _create_signature(
        self, name: str, fields: str
    ) -> sphinx.addnodes.desc_signature:
        """
        Create a predicate signature.
        """
        sig = sphinx.addnodes.desc_signature("", "")
        sig += sphinx.addnodes.desc_name("", name)
        sig["ids"].append("pred" + "-" + name)

        objs = self.env.domaindata["dl"]["objects"]
        objs.append(
            (name, name, "Predicate", self.env.docname, "pred" + "-" + name, 0)
        )

        sig += self._parse_predicate_fields(fields)
        return sig

    def _parse_docstring(self, comment_text, line_number) -> nodes.paragraph:
        """
        parse comment into a paragraph
        """
        paragraph = nodes.paragraph()
        c = ViewList()
        for i, line in enumerate(comment_text.splitlines()):
            c.append(line, str(self.sourcepath), line_number + i)
        self.state.nested_parse(c, 0, paragraph)
        return paragraph

    def _parse_preceding_comment(
        self, preceding_text: str, initial_line_number: int
    ) -> sphinx.addnodes.desc_content:
        """
        Parse the preceding comment to a directive
        """
        content = sphinx.addnodes.desc_content()
        # Find stringdocs comments right at the end of the string
        doc_comments = list(
            re.finditer(r"/\*\*([^*]|(\*+([^*/])))*\*/$", preceding_text)
        )
        if len(doc_comments) == 0:
            return content
        last_match = doc_comments[-1]
        comment_text = last_match.group(0)[len("/**") : -len("*/")]
        # get original line number
        comment_line_number = initial_line_number + preceding_text[
            0 : last_match.start()
        ].count("\n")
        content += self._parse_docstring(comment_text, comment_line_number)
        return content

    def _create_module_description(
        self, text: str, line_number: int
    ) -> sphinx.addnodes.desc_content:
        """
        Parse the first doctring in the file
        """
        content = sphinx.addnodes.desc_content()
        for match in re.finditer(r"/\*\*([^*]|(\*+([^*/])))*\*/", text):
            if match.end() < len(text):
                comment_text = match.group(0)[len("/**") : -len("*/")]
                content += self._parse_docstring(comment_text, line_number)
            break
        return content

    def _add_uses(self, name: str) -> nodes.paragraph:
        """
        Add predicate dependency information to
        predicate description.
        """

        def get_scc(pred: str) -> Optional[List[str]]:
            """
            Get the list of predicates in the
            same SCC of `pred`.
            """
            if pred in SCC_GRAPH.graph["mapping"]:
                scc = SCC_GRAPH.graph["mapping"][pred]
                return SCC_GRAPH.nodes[scc]["members"]
            else:
                for full_name in SCC_GRAPH.graph["mapping"]:
                    if split_component(full_name)[1] == pred:
                        scc = SCC_GRAPH.graph["mapping"][full_name]
                        return SCC_GRAPH.nodes[scc]["members"]
            # if a predicate is simplified by souffle
            # it could be absent from the SCC_GRAPH
            return None

        def get_link_text(dep: str) -> str:
            _, pred = split_component(dep)
            return f"`{dep}<{pred}>`"

        paragraph = nodes.paragraph()
        # synthesize the text and let it be parsed
        # so the parser takes care of creating references
        view = ViewList()
        line = 1

        scc_members = get_scc(name)
        if scc_members is None:
            logger.warning(
                f"Predicate {name} is not in final dependency graph"
            )
            view.append(
                "WARNING: Predicate not present in compiled "
                "Datalog program (Dead Code)",
                "dependency_graph",
                line,
            )
            self.state.nested_parse(view, 0, paragraph)
            return paragraph

        if name in DEPENDENCE_GRAPH_INV:
            uses_list = [
                get_link_text(dep)
                for dep in DEPENDENCE_GRAPH_INV[name]
                if dep not in scc_members
            ]
            if len(uses_list) > 0:
                uses_text = " - Uses: " + ", ".join(uses_list)
                view.append(uses_text, "dependency_graph", line)
                line += 1
        if name in DEPENDENCE_GRAPH:
            used_list = [
                get_link_text(dep)
                for dep in DEPENDENCE_GRAPH[name]
                if dep not in scc_members
            ]
            if len(used_list) > 0:
                used_text = " - Used by: " + ", ".join(used_list)
                view.append(used_text, "dependency_graph", line)
                line += 1

        if len(set(DEPENDENCE_GRAPH[name]) & set(scc_members)) > 0:
            scc_text = " - Recursive: " + ", ".join(
                [get_link_text(dep) for dep in scc_members]
            )
            view.append(scc_text, "dependency_graph", line)

        self.state.nested_parse(view, 0, paragraph)
        return paragraph

    def _parsefile(self):
        if not self.sourcepath.exists():
            raise ValueError("Can't find file: " + str(self.sourcepath))

        node_list = []
        # Split into [stuff, name, params, stuff2, name2, params2, ...]
        file_text = self.sourcepath.read_text()
        # find predicate declarations
        groups = re.split("\\.decl (.*)\\(([^)]*)\\)", file_text)
        line_number = 1
        node_list += self._create_module_description(groups[0], line_number)
        for i in range(2, len(groups), 3):
            preceding_text, name, fields = groups[i - 2 : i + 1]
            main = sphinx.addnodes.desc()
            main += self._create_signature(name, fields)
            main += self._parse_preceding_comment(preceding_text, line_number)
            main += self._add_uses(name)
            node_list.append(main)
            line_number += (
                preceding_text.count("\n")
                + name.count("\n")
                + fields.count("\n")
            )
        return node_list

    def run(self):
        self.env = self.state.document.settings.env
        sourcedir = Path(self.env.app.config.datalogautodoc_basedir)
        self.sourcepath = sourcedir / self.arguments[0]
        self.state.document.settings.record_dependencies.add(self.sourcepath)
        file_nodes = self._parsefile()
        return file_nodes


def load_dependence_graph():
    """
    Load the dependency graph
    into the DEPENDENCE_GRAPH and DEPENDENCE_GRAPH_INV dictionaries.
    The keys are stripped of component information.
    """
    global SCC_GRAPH
    dependencies = (
        (THIS_DIRECTORY.parent.parent / "src_docs/dependencies.csv")
        .read_text()
        .splitlines()
    )
    g = nx.DiGraph()
    for line in dependencies:
        src, dest = line.split(" ")
        g.add_edge(src, dest)
        _, src_pred = split_component(src)
        _, dest_pred = split_component(dest)
        DEPENDENCE_GRAPH[src_pred].append(dest)
        DEPENDENCE_GRAPH_INV[dest_pred].append(src)
    SCC_GRAPH = nx.algorithms.components.condensation(g)


def setup(app):
    app.add_domain(DatalogDomain)
    load_dependence_graph()
    # Config values
    StandardDomain.initial_data["labels"]["predicateindex"] = (
        "dl-pred_idx",
        "",
        "Predicate Index",
    )
    app.add_config_value(
        "datalogautodoc_basedir", str(MAIN_DIRECTORY / "src/datalog/"), "html"
    )

    # Directives
    app.add_directive("dl:autofile", AutoFileDirective)
    return {"version": "0.1"}
