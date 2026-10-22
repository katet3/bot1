"""Read the public jvm_like_ir structural contract without importing that package."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
import json


class LoweringError(ValueError):
    pass


def plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return plain(asdict(value))
    if isinstance(value, dict):
        return {key: plain(v) for key, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def read_method(value):
    if not isinstance(value, (dict, str)) and callable(getattr(value, "validate", None)):
        value.validate()
    if isinstance(value, str):
        value = json.loads(value)
    value = plain(value)
    if not isinstance(value, dict):
        raise LoweringError("Expected jvm_like_ir.Method, dict or JSON string")
    if value.get("schema_version", 1) != 1:
        raise LoweringError("Unsupported jvm_like_ir schema_version")
    required = ("name", "entry", "signature", "arguments", "local_slot_count", "blocks", "edges", "handlers")
    for key in required:
        if key not in value:
            raise LoweringError(f"Missing input field: {key}")
    if not value["signature"]:
        raise LoweringError("Method signature is required")
    return value


def kind(type_):
    return type_["kind"] if isinstance(type_, dict) else type_


def stack_kind(type_):
    k = kind(type_)
    if k in ("byte", "boolean", "short"):
        return "short"
    if k == "reference" or k.endswith("[]"):
        return "reference"
    if k in ("int", "void"):
        return k
    raise LoweringError(f"Unknown Java Card type: {k!r}")


def op_name(stmt):
    """Explicit aliases only: unknown operations always fail in the builder."""
    op = stmt["op"]
    return {
        "load": "load_local", "store": "store_local",
        "compare_signed": "compare",
        "field_load": "load_field", "field_store": "store_field",
        "new": "new_object", "arraylength": "array_length",
    }.get(op, op)


def terminator_kind(term):
    return {"if": "branch", "jump": "goto", "fallthrough": "goto"}.get(term["kind"], term["kind"])
