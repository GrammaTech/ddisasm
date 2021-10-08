from collections import defaultdict
import glob
import pydot
from pathlib import Path
import subprocess


DDISASM_ROOT = Path(__file__).resolve().parent.parent

DL_DOCS = DDISASM_ROOT / "doc" / "src_docs"


ARCHITECTURES = ["ARCH_ARM64", "ARCH_IA32", "ARCH_AMD64"]


def build_main_index() -> None:
    """
    Build the documentation files
    corresponding to each of the source files
    """
    for dl_file in sorted(
        glob.glob(f"{DDISASM_ROOT}/src/datalog/**/*.dl", recursive=True)
    ):
        dl_file = dl_file[len(f"{DDISASM_ROOT}/src/datalog/") : -len(".dl")]
        print(f"creating {dl_file} in /doc/src_docs/")
        source_doc_page = (DL_DOCS / dl_file).with_suffix(".rst")
        if not source_doc_page.parent.exists():
            source_doc_page.parent.mkdir()
        source_doc_page.write_text(
            f"{dl_file}\n"
            "==========================================\n\n"
            f".. dl:autofile:: {dl_file}.dl\n\n"
        )


def build_dependecy_graph() -> None:
    """
    Build the datalog dependency graph by calling souffle with each of the
    defined architectures. Dependencies are stored in `dependencies.csv`.
    """

    dependencies = defaultdict(set)
    for arch in ARCHITECTURES:
        print(f"computing dependency graph for {arch}")
        dot_text = subprocess.check_output(
            [
                "souffle",
                f"{DDISASM_ROOT}/src/datalog/main.dl",
                f"-M{arch}",
                "--show=precedence-graph-text",
            ]
        )
        g: pydot.Graph = pydot.graph_from_dot_data(dot_text.decode("utf8"))[0]
        for edge in g.get_edges():
            dependencies[edge.get_source().replace('"', "")].add(
                edge.get_destination().replace('"', "")
            )
    with open(DL_DOCS / "dependencies.csv", mode="w") as f:
        for src in sorted(dependencies):
            for dest in sorted(dependencies[src]):
                print(src, dest, file=f)


def build_all() -> None:
    build_main_index()
    build_dependecy_graph()
