"""Stack-free, typed three-address IR with block parameters.

Temporary values are immutable; local slots and the heap remain mutable.
This is a precursor to Jimple/Shimple, not a JVM class file representation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json

from jcvm_ir import Handler, Reference, Signature, Type


class LoweringError(ValueError):
    """The supplied JCVM IR cannot be represented safely by this stage."""


class ValueType(str, Enum):
    SHORT = 'short'
    INT = 'int'
    REFERENCE = 'reference'

    @property
    def bits(self) -> int | None:
        return {'short': 16, 'int': 32, 'reference': None}[self.value]

    @property
    def slots(self) -> int:
        return 2 if self is ValueType.INT else 1

    @classmethod
    def of(cls, typ: Type) -> ValueType:
        try:
            return cls(typ.stack_kind)
        except ValueError as exc:
            raise LoweringError(f'Unsupported computation type {typ.kind}') from exc


@dataclass(frozen=True)
class Value:
    name: str
    type: ValueType


@dataclass(frozen=True)
class Constant:
    value: int | None
    type: ValueType


Operand = Value | Constant


@dataclass(frozen=True)
class Argument:
    slot: int
    declared_type: Type
    is_receiver: bool = False


@dataclass(frozen=True)
class Statement:
    id: str
    offset: int
    op: str
    operands: tuple[Operand, ...] = ()
    result: Value | None = None
    semantic_type: Type | None = None
    local_index: int | None = None
    reference: Reference | None = None
    mode: str | None = None
    may_throw: bool = False
    handler_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class Terminator:
    offset: int
    kind: str
    operands: tuple[Operand, ...] = ()
    relation: str | None = None
    handler_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class Edge:
    source: int
    target: int
    kind: str
    arguments: tuple[Operand, ...] = ()
    case_value: int | None = None
    handler_index: int | None = None


@dataclass(frozen=True)
class Block:
    id: int
    start_offset: int
    parameters: tuple[Value, ...]
    statements: tuple[Statement, ...]
    terminator: Terminator
    # Includes offsets of constants, dup/pop and nop eliminated during lowering.
    source_offsets: tuple[int, ...]


@dataclass(frozen=True)
class Method:
    name: str
    entry: int
    signature: Signature
    arguments: tuple[Argument, ...]
    local_slot_count: int
    blocks: tuple[Block, ...]
    edges: tuple[Edge, ...]
    handlers: tuple[Handler, ...]
    warnings: tuple[str, ...] = ()
    schema_version: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    def to_text(self) -> str:
        from .text import format_method
        return format_method(self)

    def validate(self) -> None:
        from .validation import validate
        validate(self)
