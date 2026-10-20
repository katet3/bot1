"""Jimple method fragments for inspection; JSON is the authoritative interchange."""
from .model import Expr, Value

OPERATORS = {"add": "+", "sub": "-", "mul": "*", "div": "/", "rem": "%", "and": "&", "or": "|", "xor": "^", "shl": "<<", "shr": ">>", "ushr": ">>>", "eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">="}


def render(value):
    if isinstance(value, Value):
        if value.kind == "local":
            return value.name
        if value.kind == "constant":
            return "null" if value.value is None else str(value.value)
        if value.kind == "this":
            return f"@this: {value.type}"
        if value.kind == "parameter":
            return f"@parameter{value.index}: {value.type}"
        if value.kind == "caught_exception":
            return "@caughtexception"
    if not isinstance(value, Expr):
        raise ValueError(f"Cannot render {value!r}")
    args = [render(v) for v in value.operands]
    if value.kind in ("binary", "condition"):
        return f"{args[0]} {OPERATORS[value.operator]} {args[1]}"
    if value.kind == "unary":
        return f"neg {args[0]}"
    if value.kind == "cast":
        return f"({value.type}) {args[0]}"
    if value.kind == "length":
        return f"lengthof {args[0]}"
    if value.kind == "array":
        return f"{args[0]}[{args[1]}]"
    if value.kind == "field":
        return (args[0] + "." if args else "") + value.field.signature
    if value.kind == "new":
        return f"new {value.type}"
    if value.kind == "new_array":
        return f"newarray ({value.type[:-2]})[{args[0]}]"
    if value.kind == "invoke":
        receiver, parameters = ("", args) if value.mode == "static" else (args[0] + ".", args[1:])
        return f"{value.mode}invoke {receiver}{value.method.signature}({', '.join(parameters)})"
    raise ValueError(f"Cannot render expression {value.kind}")


def method_text(method):
    s = method.symbol
    lines = [f"// {method.source_name}", f"// owner: {s.owner}",
             f"{'static ' if s.is_static else ''}{s.returns} {s.name}({', '.join(s.params)})", "{"]
    lines.extend(f"    {local.type} {local.name};" for local in method.locals)
    lines.append("")
    for unit in method.units:
        left = render(unit.left) if unit.left is not None else ""
        right = render(unit.right) if unit.right is not None else ""
        k = unit.kind
        if k in ("assign", "identity"):
            statement = f"{left} {':=' if k == 'identity' else '='} {right};"
        elif k == "goto":
            statement = f"goto L{unit.target};"
        elif k == "if":
            statement = f"if {right} goto L{unit.target};"
        elif k == "switch":
            statement = f"lookupswitch({right}) {{ " + " ".join(f"case {v}: goto L{t};" for v, t in unit.cases) + f" default: goto L{unit.default_target}; }};"
        elif k == "return_void":
            statement = "return;"
        elif k == "return":
            statement = f"return {right};"
        elif k == "throw":
            statement = f"throw {right};"
        else:
            statement = f"{right};"
        source = f" // CAP @{unit.offset}" if unit.offset is not None else ""
        lines.append(f"L{unit.label}: {statement}{source}")
    if any(t.end == len(method.units) for t in method.traps):
        lines.append(f"L{len(method.units)}: nop;")
    for trap in sorted(method.traps, key=lambda t: (t.priority, t.begin)):
        lines.append(f"    catch {trap.exception_type} from L{trap.begin} to L{trap.end} with L{trap.handler}; // handler #{trap.priority}, stop_bit={int(trap.stop_bit)}")
    lines.append("}")
    return "\n".join(lines) + "\n"
