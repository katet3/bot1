"""Converted objects plus CAP metadata not represented by SootMethod itself."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields, is_dataclass
import json
from pathlib import Path
from typing import Any

from soot_ir import Local, MethodRef, FieldRef, Trap

from .errors import AdapterError
from .metadata import ProgramMetadata


@dataclass(frozen=True)
class MethodDetails:
    source_name: str
    locals: tuple[Local, ...]
    traps: tuple[Trap, ...]
    source_map: tuple[tuple[int, tuple[int, ...]], ...]
    # (label, CAP bytecode offset, source block, source statement, handler indices)
    unit_origins: tuple[tuple[int, int | None, int | None, str | None, tuple[int, ...]], ...]
    normal_successors: tuple[tuple[int, tuple[int, ...]], ...]
    required_backend_features: tuple[str, ...]
    warnings: tuple[str, ...]


def _node(value):
    """Diagnostic JSON for acyclic expression/statement trees, not a pickle."""
    if is_dataclass(value):
        return {"node": type(value).__name__, **{f.name: _node(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, Mapping):
        return {str(k): _node(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_node(v) for v in value]
    return value


@dataclass(frozen=True)
class AdaptedProgram:
    # Values are actual pysoot.sootir classes, not lookalike wrapper nodes.
    classes: Mapping[str, Any]
    methods: Mapping[str, Any]  # Stable CAP method key -> SootMethod.
    details: Mapping[str, MethodDetails]
    metadata: ProgramMetadata
    external_methods: tuple[MethodRef, ...]
    external_fields: tuple[FieldRef, ...]
    external_classes: tuple[str, ...]
    unresolved_symbols: tuple[str, ...]
    backend_version: str
    target_revision: str

    @property
    def required_backend_features(self):
        features = {f for d in self.details.values() for f in d.required_backend_features}
        if any(m.token is not None and not {"STATIC", "PRIVATE", "CONSTRUCTOR"}.intersection(m.attrs)
               for c in self.metadata.classes for m in c.methods):
            # Synthetic per-offset names do not establish Java override relations.
            features.add("cap_virtual_dispatch")
        return tuple(sorted(features))

    def require_resolved_symbols(self):
        if self.unresolved_symbols:
            raise AdapterError("Symbol bindings required: " + ", ".join(self.unresolved_symbols))

    def require_backend_features(self, supported):
        missing = set(self.required_backend_features) - set(supported)
        if missing:
            raise AdapterError("Backend features required: " + ", ".join(sorted(missing)))

    def method_to_dict(self, key):
        method, details = self.methods[key], self.details[key]
        return {
            "key": key, "class_name": method.class_name, "name": method.name,
            "ret": method.ret, "params": method.params, "attrs": method.attrs,
            "exceptions": method.exceptions,
            "blocks": [_node(block) for block in method.blocks],
            "basic_cfg": {str(b.idx): [s.idx for s in succs] for b, succs in method.basic_cfg.items()},
            "exceptional_preds": {str(b.idx): [s.idx for s in preds] for b, preds in method.exceptional_preds.items()},
            "cap": asdict(details),
        }

    def to_dict(self):
        return {
            "schema": "cap2soot.pysoot_adapter.program/1",
            "pysoot": {"installed_version": self.backend_version, "target_revision": self.target_revision},
            "classes": [
                {"name": c.name, "super_class": c.super_class, "interfaces": c.interfaces,
                 "attrs": c.attrs, "fields": dict(c.fields),
                 "methods": [k for k, m in self.methods.items() if m.class_name == c.name]}
                for c in self.classes.values()
            ],
            "methods": [self.method_to_dict(k) for k in self.methods],
            "declarations": asdict(self.metadata),
            "external_methods": [asdict(m) for m in self.external_methods],
            "external_fields": [asdict(f) for f in self.external_fields],
            "external_classes": self.external_classes,
            "unresolved_symbols": self.unresolved_symbols,
            "required_backend_features": self.required_backend_features,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def method_to_text(self, key):
        method, details = self.methods[key], self.details[key]
        lines = [f"{method.class_name}.{method.name}({', '.join(method.params)}) -> {method.ret}",
                 f"CAP key: {key}", f"Attributes: {', '.join(method.attrs)}"]
        for block in method.blocks:
            lines.append(f"B{block.idx} label={block.label}")
            for stmt in block.statements:
                lines.append(f"  {stmt.label} @{stmt.offset}: {type(stmt).__name__}: {stmt}")
            lines.append(f"  successors: {[s.idx for s in method.basic_cfg.get(block, ())]}")
        if details.traps:
            lines.append("Traps: " + json.dumps([asdict(t) for t in details.traps]))
        return "\n".join(lines) + "\n"

    def export(self, output_dir: Path):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "program.json").write_text(self.to_json(), encoding="utf-8")
        for index, key in enumerate(self.methods):
            (output_dir / f"method_{index}.json").write_text(
                json.dumps(self.method_to_dict(key), ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (output_dir / f"method_{index}.txt").write_text(self.method_to_text(key), encoding="utf-8")
