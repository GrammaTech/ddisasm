import importlib.resources as native_importlib_resources
import pathlib
import platform
from contextlib import contextmanager
from typing import Iterator

from .version import __version__

if hasattr(native_importlib_resources, "files"):
    importlib_resources = native_importlib_resources
else:
    import importlib_resources  # type: ignore


__all__ = ["ddisasm_path", "__version__"]


@contextmanager
def ddisasm_path() -> Iterator[pathlib.Path]:
    """
    Retrieves the path on disk to the ddisasm executable.
    """

    if platform.system() == "Windows":
        executable_name = "ddisasm.exe"
    else:
        executable_name = "ddisasm"

    template_path = importlib_resources.files(__package__) / executable_name
    with importlib_resources.as_file(template_path) as actual_path:
        yield actual_path
