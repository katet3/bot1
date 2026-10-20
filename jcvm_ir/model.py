"""Typed stack IR. Offsets are relative to the first bytecode of a method."""
from dataclasses import dataclass, field, asdict
from enum import Enum
import json


class IRValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Type:
    kind: str
    class_ref: int | None = None

    @property
    def stack_kind(self):
        if self.kind in ('boolean', 'byte', 'short'):
            return 'short'
        if self.kind == 'reference' or self.kind.endswith('[]'):
            return 'reference'
        return self.kind

    @property
    def slots(self):
        return 0 if self.kind == 'void' else 2 if self.kind == 'int' else 1


SHORT = Type('short')
INT = Type('int')
REF = Type('reference')
VOID = Type('void')


@dataclass(frozen=True)
class Signature:
    parameters: tuple[Type, ...]
    returns: Type


@dataclass(frozen=True)
class Reference:
    cp_index: int
    tag: int
    package_aid: str
    package_version: tuple[int, int]
    external: bool
    class_token: int | None = None
    class_offset: int | None = None
    member_token: int | None = None
    internal_offset: int | None = None
    signature: Signature | None = None
    field_type: Type | None = None


class Op(str, Enum):
    NOP = 'nop'
    CONST = 'const'
    LOAD = 'load_local'
    STORE = 'store_local'
    STACK = 'stack'
    BINARY = 'binary'
    UNARY = 'unary'
    CONVERT = 'convert'
    COMPARE = 'compare'
    INCREMENT = 'increment_local'
    FIELD_LOAD = 'load_field'
    FIELD_STORE = 'store_field'
    ARRAY_LOAD = 'array_load'
    ARRAY_STORE = 'array_store'
    ARRAY_LENGTH = 'array_length'
    NEW = 'new_object'
    NEW_ARRAY = 'new_array'
    CALL = 'call'
    BRANCH = 'branch'
    GOTO = 'goto'
    SWITCH = 'switch'
    RETURN = 'return'
    THROW = 'throw'


@dataclass(frozen=True)
class Operation:
    offset: int
    mnemonic: str
    op: Op
    value_type: Type = VOID
    args: tuple = ()
    reference: Reference | None = None
    # Logical values, bottom-to-top; int occupies two JCVM slots.
    pops: tuple[Type, ...] = ()
    pushes: tuple[Type, ...] = ()
    targets: tuple[int, ...] = ()
    cases: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Handler:
    start: int
    end: int  # exclusive
    target: int
    catch_type_index: int
    stop_bit: bool = False


@dataclass(frozen=True)
class Edge:
    source: int
    target: int
    kind: str
    case_value: int | None = None
    handler_index: int | None = None


@dataclass
class Block:
    id: int
    start: int
    operations: list[Operation]
    input_stack: tuple[str, ...] | None = None
    output_stack: tuple[str, ...] | None = None


@dataclass
class MethodIR:
    name: str
    blocks: list[Block]
    edges: list[Edge]
    handlers: tuple[Handler, ...]
    entry: int | None
    max_stack: int
    nargs: int
    max_locals: int
    signature: Signature | None
    warnings: list[str] = field(default_factory=list)

    def to_json(self):
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    def to_text(self):
        lines = [f'method {self.name} stack={self.max_stack} args={self.nargs} locals={self.max_locals}']
        for block in self.blocks:
            lines.append(f'B{block.id} @{block.start} stack_in={block.input_stack}')
            for op in block.operations:
                ref = f' cp#{op.reference.cp_index}={op.reference}' if op.reference else ''
                targets = f' targets={op.targets} cases={op.cases}' if op.targets else ''
                lines.append(f'  {op.offset}: {op.op.value}<{op.value_type.kind}> {op.args}{ref}{targets}')
            for edge in self.edges:
                if edge.source == block.id:
                    lines.append(f'  -> B{edge.target} {edge.kind} case={edge.case_value}')
        lines.extend('WARNING: '+w for w in self.warnings)
        return '\n'.join(lines)
