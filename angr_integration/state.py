"""Typed arguments for a direct method call; no implicit APDU or heap stubs."""
from dataclasses import dataclass

from .errors import LoaderError
from .heap_types import PRIMITIVES, is_reference_type


@dataclass(frozen=True)
class SymbolicArgument:
    name: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise LoaderError("Symbolic argument must have a nonempty name")


def encode_argument(value, type_, deps):
    if type_ not in PRIMITIVES:
        raise LoaderError(f"Arguments of type {type_} need an explicit heap/API model")
    bits = PRIMITIVES[type_]
    bv = deps.claripy
    if isinstance(value, SymbolicArgument):
        raw = bv.BVS(value.name, bits, explicit_name=True)
    elif isinstance(value, int):
        lo, hi = (0, 1) if type_ == "boolean" else (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
        if not lo <= value <= hi:
            raise LoaderError(f"Argument {value} is outside the {type_} range [{lo}, {hi}]")
        raw = bv.BVV(value & ((1 << bits) - 1), bits)
    elif isinstance(value, bv.ast.BV):
        if value.size() != bits:
            raise LoaderError(f"A {type_} argument requires a {bits}-bit bitvector, got {value.size()}")
        raw = value
    else:
        raise LoaderError(f"Unsupported {type_} argument: {type(value).__name__}")
    if bits == 32:
        normalized = raw
    elif type_ == "boolean":
        normalized = raw.zero_extend(32 - bits)
    else:
        normalized = raw.sign_extend(32 - bits)
    return deps.arch.SootArgument(normalized, type_), raw


def create_call_state(loaded, method_key, args=(), *, receiver=None, base_state=None):
    method = loaded.index.method(method_key)
    if len(args) != len(method.params):
        raise LoaderError(f"{method_key} expects {len(method.params)} arguments, got {len(args)}")
    if base_state is not None and base_state.project is not loaded.project:
        raise LoaderError("base_state belongs to another angr project")
    if base_state is not None and not base_state.has_plugin("cap_heap"):
        raise LoaderError("base_state must contain a CAP heap; use create_heap_state()")
    is_static = "STATIC" in method.attrs
    if is_static and receiver is not None:
        raise LoaderError("Static methods do not take a receiver")
    if not is_static:
        if receiver is None:
            raise LoaderError(f"An explicit receiver of type {method.class_name} is required")
        if base_state is None:
            raise LoaderError("Pass the base_state containing the receiver's heap")
        base_state.cap_heap.validate_reference(receiver, method.class_name, nullable=False)
    # No method body or class initializer is run when preparing this state.
    loaded.readiness.require(method_key)
    names = [a.name for a in args if isinstance(a, SymbolicArgument)]
    if len(names) != len(set(names)):
        raise LoaderError("Symbolic argument names must be unique (reuse a BV explicitly for aliasing)")
    encoded, inputs = [], []
    if receiver is not None:
        encoded.append(loaded.dependencies.arch.SootArgument(receiver, method.class_name, is_this_ref=True))
    for value, type_ in zip(args, method.params, strict=True):
        if is_reference_type(type_):
            null_type = loaded.dependencies.arch.SootNullConstant
            raw = null_type() if value is None else value
            if not isinstance(raw, null_type):
                if base_state is None:
                    raise LoaderError("Reference arguments need the base_state containing their heap")
                base_state.cap_heap.validate_reference(raw, type_)
            argument = loaded.dependencies.arch.SootArgument(raw, type_)
        else:
            argument, raw = encode_argument(value, type_, loaded.dependencies)
        encoded.append(argument)
        inputs.append(raw)
    kwargs = {} if base_state is None else {"base_state": base_state}
    # Always use a terminator, including with base_state. Otherwise angr uses
    # base_state.addr as the return address and accidentally resumes that code.
    state = loaded.project.factory.call_state(
        loaded.method_address(method_key), *encoded,
        ret_addr=loaded.dependencies.arch.SootAddressTerminator(), **kwargs,
    )
    state.globals["cap2soot.entry_key"] = method_key
    state.globals["cap2soot.inputs"] = tuple(inputs)
    return state

