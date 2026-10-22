"""Lazy, version-checked imports; the IR-only pipeline does not require angr."""
from functools import lru_cache
from importlib import import_module, metadata
from types import SimpleNamespace

from pysoot_adapter.backend import load_backend

from .errors import DependencyError


VERSIONS = {"angr": "10.0.4.post1", "cle": "10.0.4", "archinfo": "10.0.4"}
INSTALL_HINT = "python -m pip install -r requirements-angr.txt (Python >= 3.12)"


@lru_cache(maxsize=1)
def load_dependencies():
    load_backend()
    try:
        for package, expected in VERSIONS.items():
            actual = metadata.version(package)
            if actual != expected:
                raise DependencyError(
                    f"Unsupported {package} {actual}; tested version: {expected}. {INSTALL_HINT}"
                )
        angr = import_module("angr")
        arch = import_module("archinfo.arch_soot")
        return SimpleNamespace(angr=angr, claripy=angr.claripy, arch=arch)
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise DependencyError(
            f"angr dependency unavailable: {exc}. {INSTALL_HINT}. "
            "Use --no-angr to export the preceding IR stages."
        ) from exc

