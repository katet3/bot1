"""Invariants required by the subsequent pysoot adapter."""
from collections import deque
import re

from .input import LoweringError
from .model import Expr, Value


def validate(method):
    def fail(message):
        raise LoweringError(f"{method.source_name}: invalid soot_ir: {message}")

    units = method.units
    if not units or [u.label for u in units] != list(range(len(units))):
        fail("Unit labels must be contiguous from 0")
    local_types = {local.name: local.type for local in method.locals}
    if len(local_types) != len(method.locals):
        fail("Duplicate local")
    primitive = {"int", "short", "byte", "boolean"}

    def compatible(source, target):
        if source == target:
            return True
        if source == "null":
            return target not in primitive | {"void"}
        if source not in primitive and target == "java.lang.Object":
            return True
        return False

    def check_value(value):
        if isinstance(value, Value):
            if value.kind == "local":
                if local_types.get(value.name) != value.type:
                    fail(f"Undeclared or mistyped local {value.name}")
            elif value.kind not in ("constant", "this", "parameter", "caught_exception"):
                fail(f"Unknown value kind {value.kind}")
        elif isinstance(value, Expr):
            for operand in value.operands:
                if not isinstance(operand, Value) or operand.kind not in ("local", "constant"):
                    fail("Expression operands must be immediates")
                check_value(operand)
            if value.kind in ("binary", "condition"):
                if len(value.operands) != 2:
                    fail("Binary expression arity")
                if value.kind == "binary" and (value.type != "int" or any(v.type != "int" for v in value.operands)):
                    fail("Arithmetic must operate on explicit 32-bit int values")
                if value.kind == "condition":
                    types = [v.type for v in value.operands]
                    if any(t in primitive for t in types) and types != ["int", "int"]:
                        fail("Condition numeric operands must be int")
                    if not any(t in primitive for t in types) and value.operator not in ("eq", "ne"):
                        fail("Reference comparisons support only eq/ne")
            elif value.kind == "invoke":
                ref = value.method
                if ref is None or value.type != ref.returns or value.mode not in ("static", "special", "virtual", "interface"):
                    fail("Incomplete invocation descriptor")
                nreceiver = 0 if ref.is_static else 1
                if len(value.operands) != nreceiver + len(ref.params):
                    fail("Invocation arity")
                if nreceiver and value.operands[0].type != ref.owner:
                    fail("Receiver type must be explicit")
                if any(not compatible(v.type, t) for v, t in zip(value.operands[nreceiver:], ref.params)):
                    fail("Invocation argument type mismatch")
            elif value.kind == "field":
                if value.field is None or len(value.operands) != (not value.field.is_static):
                    fail("Field reference arity")
            elif value.kind not in ("cast", "unary", "length", "array", "new", "new_array"):
                fail(f"Unknown expression kind {value.kind}")
        else:
            fail("Malformed expression/value")

    def check_target(label):
        if type(label) is not int or not 0 <= label < len(units):
            fail(f"Dangling Unit target {label}")

    for local in method.locals:
        if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", local.name):
            fail("Invalid local identifier")
    for unit in units:
        if unit.left is not None:
            check_value(unit.left)
        if unit.right is not None:
            check_value(unit.right)
        if unit.kind in ("assign", "identity"):
            if unit.left is None or unit.right is None or not compatible(unit.right.type, unit.left.type):
                fail(f"Assignment type mismatch at Unit {unit.label}")
            if isinstance(unit.left, Value) and unit.left.kind != "local":
                fail("Assignment target must be a local, field or array element")
            if isinstance(unit.left, Expr) and unit.left.kind not in ("field", "array"):
                fail("Invalid lvalue")
            if unit.kind == "identity" and (not isinstance(unit.right, Value) or unit.right.kind not in ("this", "parameter", "caught_exception")):
                fail("Invalid identity RHS")
        elif unit.kind == "if":
            if not isinstance(unit.right, Expr) or unit.right.kind != "condition":
                fail("If requires condition")
            check_target(unit.target)
        elif unit.kind == "goto":
            check_target(unit.target)
        elif unit.kind == "switch":
            if not isinstance(unit.right, Value) or unit.right.type != "int":
                fail("Switch needs an int immediate")
            check_target(unit.default_target)
            for _, target in unit.cases:
                check_target(target)
        elif unit.kind == "return":
            if unit.right is None or not compatible(unit.right.type, method.symbol.returns):
                fail("Return type mismatch")
        elif unit.kind == "return_void":
            if method.symbol.returns != "void":
                fail("Void return in a value-returning method")
        elif unit.kind == "invoke":
            if not isinstance(unit.right, Expr) or unit.right.kind != "invoke" or unit.right.type != "void":
                fail("InvokeStmt requires void call")
        elif unit.kind == "throw":
            if not isinstance(unit.right, Value) or unit.right.type != "java.lang.Throwable":
                fail("Throw needs explicit Throwable reference")
        else:
            fail(f"Unknown statement kind {unit.kind}")
    for trap in method.traps:
        if not 0 <= trap.begin < trap.end <= len(units):
            fail("Invalid trap interval")
        check_target(trap.handler)
        handler = units[trap.handler]
        if handler.kind != "identity" or handler.right.kind != "caught_exception":
            fail("Trap target must start with @caughtexception identity")
    covered = [label for block in method.blocks for label in block.unit_labels]
    if covered != list(range(len(units))):
        fail("Blocks must partition the Unit sequence")
    from .builder import make_blocks
    if make_blocks(units, method.traps) != method.blocks:
        fail("Block successor tables do not match units/traps")

    # A use must be defined on every path reaching that Unit. Exceptional paths
    # observe the locals BEFORE the potentially throwing assignment completes.
    def uses(value):
        if isinstance(value, Value):
            return {value.name} if value.kind == "local" else set()
        if isinstance(value, Expr):
            return {v.name for v in value.operands if v.kind == "local"}
        return set()

    states, queue = {0: frozenset()}, deque([0])

    def propagate(label, defined):
        if label in states:
            defined = states[label] & defined
        if states.get(label) != defined:
            states[label] = defined
            queue.append(label)

    while queue:
        label = queue.popleft()
        unit, before = units[label], states[label]
        required = uses(unit.right) | (uses(unit.left) if isinstance(unit.left, Expr) else set())
        if not required <= before:
            fail(f"Use before definition at Unit {label}: {sorted(required - before)}")
        for trap in method.traps:
            if trap.begin <= label < trap.end:
                propagate(trap.handler, before)
        after = before | ({unit.left.name} if unit.kind in ("assign", "identity") and isinstance(unit.left, Value) else set())
        if unit.kind in ("goto", "if"):
            propagate(unit.target, after)
        if unit.kind == "switch":
            for _, target in unit.cases:
                propagate(target, after)
            propagate(unit.default_target, after)
        if unit.kind not in ("goto", "switch", "return", "return_void", "throw"):
            if label + 1 >= len(units):
                fail("Execution falls off the method")
            propagate(label + 1, after)
