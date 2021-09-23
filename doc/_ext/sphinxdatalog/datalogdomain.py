from sphinx.domains import Domain
from docutils.parsers.rst import directives
from sphinx.roles import XRefRole
from sphinx.directives import ObjectDescription
from sphinx.util.nodes import make_refnode
from sphinx import addnodes


class PredicateNode(ObjectDescription):
    """A custom node that describes a recipe."""

    required_arguments = 1

    option_spec = {"contains": directives.unchanged_required}

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name(text=sig)
        signode += addnodes.desc_type(text="Predicate")
        return sig

    def add_target_and_index(self, name_cls, sig, signode):
        signode["ids"].append("recipe" + "-" + sig)
        # if 'noindex' not in self.options:
        #    name = "{}.{}.{}".format('dl', type(self).__name__, sig)
        #    objs = self.env.domaindata['dl']['objects']
        #    objs.append((name,
        #                 sig,
        #                 'Recipe',
        #                 self.env.docname,
        #                 'recipe' + '-' + sig,
        #                 0))


class DatalogDomain(Domain):
    name = "dl"
    label = "Datalog"

    roles = {"reref": XRefRole()}

    directives = {
        "pred": PredicateNode,
    }

    # indices = {
    #    RecipeIndex,
    #    IngredientIndex
    # }

    initial_data = {
        "objects": [],  # object list
    }

    def get_full_qualified_name(self, node):
        """Return full qualified name for a given node"""
        return "{}.{}.{}".format("dl", type(node).__name__, node.arguments[0])

    def get_objects(self):
        for obj in self.data["objects"]:
            yield (obj)

    def resolve_xref(
        self, env, fromdocname, builder, typ, target, node, contnode
    ):

        match = [
            (docname, anchor)
            for name, sig, typ, docname, anchor, prio in self.get_objects()
            if sig == target
        ]

        if len(match) > 0:
            todocname = match[0][0]
            targ = match[0][1]

            return make_refnode(
                builder, fromdocname, todocname, targ, contnode, targ
            )
        else:
            print("Awww, found nothing")
            return None


def setup(app):
    app.add_domain(DatalogDomain)
    return {"version": "0.1"}
