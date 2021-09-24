import glob

from pathlib import Path

DDISASM_ROOT = Path(__file__).resolve().parent.parent

index_prefix = """
Source files
=============================

.. toctree::
    :maxdepth: 2

"""
index_suffix = """
:ref:`predicateindex`
"""


def build_main_index():
    index_text = index_prefix
    dl_docs = DDISASM_ROOT / "doc" / "src_docs"
    for dl_file in sorted(
        glob.glob(f"{DDISASM_ROOT}/src/datalog/**/*.dl", recursive=True)
    ):
        dl_file = dl_file[len(f"{DDISASM_ROOT}/src/datalog/") : -len(".dl")]
        print(f"adding {dl_file} to index")
        (dl_docs / dl_file).with_suffix(".rst").write_text(
            f"{dl_file}\n"
            "==========================================\n\n"
            f".. dl:autofile:: {dl_file}.dl\n\n"
        )
        index_text += f"    src_docs/{dl_file}.rst\n"
    index_text += index_suffix
    (DDISASM_ROOT / "doc" / "index.rst").write_text(index_text)


if __name__ == "__main__":
    build_main_index()
