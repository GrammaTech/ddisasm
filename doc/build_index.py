import glob

from pathlib import Path

DDISASM_ROOT = Path(__file__).resolve().parent.parent


def build_main_index() -> None:
    """
    Build the documentation files
    corresponding to each of the source files
    """
    dl_docs = DDISASM_ROOT / "doc" / "src_docs"
    for dl_file in sorted(
        glob.glob(f"{DDISASM_ROOT}/src/datalog/**/*.dl", recursive=True)
    ):
        dl_file = dl_file[len(f"{DDISASM_ROOT}/src/datalog/") : -len(".dl")]
        print(f"creating {dl_file} in /doc/src_docs/")
        source_doc_page = (dl_docs / dl_file).with_suffix(".rst")
        if not source_doc_page.parent.exists():
            source_doc_page.parent.mkdir()
        source_doc_page.write_text(
            f"{dl_file}\n"
            "==========================================\n\n"
            f".. dl:autofile:: {dl_file}.dl\n\n"
        )


if __name__ == "__main__":
    build_main_index()
