"""Serializable, typed Jimple body. This is the input contract for pysoot_adapter."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class Local:
    name: str
    type: str


@dataclass(frozen=True)
class Value:
    kind: str                 # local, constant, this, parameter, caught_exception
    type: str
    name: str | None = None
    value: int | None = None
    index: int | None = None


@dataclass(frozen=True)
class MethodRef:
    key: str
    owner: str
    name: str
    params: tuple[str, ...]
    returns: str
    is_static: bool
    resolved: bool = True

    @property
    def signature(self):
        return f"<{self.owner}: {self.returns} {self.name}({','.join(self.params)})>"


@dataclass(frozen=True)
class FieldRef:
    key: str
    owner: str
    name: str
    type: str
    is_static: bool
    resolved: bool = True

    @property
    def signature(self):
        return f"<{self.owner}: {self.type} {self.name}>"


@dataclass(frozen=True)
class Expr:
    kind: str
    type: str
    operands: tuple[Value, ...] = ()
    operator: str | None = None
    method: MethodRef | None = None
    field: FieldRef | None = None
    mode: str | None = None


@dataclass(frozen=True)
class Unit:
    label: int
    kind: str
    offset: int | None
    source_block: int | None
    source_statement: str | None = None
    left: Value | Expr | None = None
    right: Value | Expr | None = None
    target: int | None = None
    cases: tuple[tuple[int, int], ...] = ()
    default_target: int | None = None
    handlers: tuple[int, ...] = ()


@dataclass(frozen=True)
class Block:
    index: int
    label: int
    unit_labels: tuple[int, ...]
    successors: tuple[int, ...]        # block indices, not Unit labels
    exceptional_successors: tuple[int, ...]


@dataclass(frozen=True)
class Trap:
    begin: int                        # inclusive Unit label
    end: int                          # exclusive Unit label
    handler: int                      # bridge with @caughtexception
    exception_type: str
    priority: int                     # index in original ordered handler table
    stop_bit: bool


@dataclass(frozen=True)
class Method:
    source_name: str
    symbol: MethodRef
    locals: tuple[Local, ...]
    units: tuple[Unit, ...]
    blocks: tuple[Block, ...]
    traps: tuple[Trap, ...]
    source_map: tuple[tuple[int, tuple[int, ...]], ...]
    warnings: tuple[str, ...] = ()
    required_backend_features: tuple[str, ...] = ()
    schema: str = "cap2soot.soot_ir.method/1"

    def to_json(self, **kwargs):
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, **kwargs)

    def to_text(self):
        from .text import method_text
        return method_text(self)

    def validate(self):
        from .validation import validate
        validate(self)


@dataclass(frozen=True)
class Program:
    methods: tuple[Method, ...]
    unresolved_symbols: tuple[str, ...]
    schema: str = "cap2soot.soot_ir.program/1"

    def to_json(self, **kwargs):
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, **kwargs)

    def require_resolved_symbols(self):
        if self.unresolved_symbols:
            raise ValueError("Symbol bindings required: " + ", ".join(self.unresolved_symbols))
