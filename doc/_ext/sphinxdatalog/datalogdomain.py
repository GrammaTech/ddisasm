from sphinx.domains import Domain, ObjType


class DatalogDomain(Domain):
    """
    Datalog language domain.
    """
    name = "dl"
    label = "Datalog"


def setup(app):
    app.add_domain(DatalogDomain)
