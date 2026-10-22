"""CAP-aware adapter from soot_ir to the pysoot Python object model."""
from .builder import PySootAdapter
from .cap_metadata import metadata_from_cap
from .errors import AdapterError, DependencyError
from .metadata import AppletMetadata, ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata
from .model import AdaptedProgram, MethodDetails

__all__ = [
    "PySootAdapter", "metadata_from_cap", "AdapterError", "DependencyError",
    "AppletMetadata", "ClassMetadata", "FieldMetadata", "MethodMetadata", "ProgramMetadata",
    "AdaptedProgram", "MethodDetails",
]
