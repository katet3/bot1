"""Conservative execution profile for testing the loader with the stock Soot semantics.

All adapted bodies can be loaded. Only this explicitly checked subset may be
executed until Java Card heap, API, dispatch and exception models are added.
"""
from dataclasses import asdict, dataclass, fields, is_dataclass

from .errors import ExecutionNotReady


PRIMITIVES = {"byte": 8, "short": 16, "int": 32, "boolean": 1}
SUPPORTED_FEATURES = frozenset({
    "unit_label_targets", "int32_wraparound", "signed_int_comparisons", "primitive_casts",
})
# Calls are checked individually and transitively, not accepted as a feature wholesale.
CHECKED_FEATURES = SUPPORTED_FEATURES | {"java_calls_and_api_models"}
SAFE_BINOPS = frozenset({"add", "sub", "mul", "and", "or", "xor"})
STATEMENTS = frozenset({"IdentityStmt", "AssignStmt", "IfStmt", "GotoStmt",
                        "LookupSwitchStmt", "ReturnStmt", "ReturnVoidStmt", "InvokeStmt"})
VALUES = frozenset({"SootLocal", "SootIntConstant", "SootParamRef", "SootThisRef"})


@dataclass(frozen=True, order=True)
class ExecutionIssue:
    method_key: str
    code: str
    message: str
    unit_label: int = -1

    def to_dict(self):
        return asdict(self)


def walk(value):
    if is_dataclass(value):
        yield value
        for field in fields(value):
            yield from walk(getattr(value, field.name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from walk(item)


class ExecutionReadiness:
    def __init__(self, program, index):
        self.program, self.index = program, index
        self.local_issues = {}
        self.calls = {}
        for key, method in program.methods.items():
            issues, calls = set(), set()

            def add(code, message, label=-1):
                issues.add(ExecutionIssue(key, code, message, label))

            if not method.blocks or {"ABSTRACT", "NATIVE"}.intersection(method.attrs):
                add("missing_body", "Abstract/native method has no supported executable body")
            if method.name == "<clinit>":
                add("class_initialization", "Class initialization needs a separate CAP state model")
            if any(ty not in PRIMITIVES for ty in method.params) or method.ret not in {*PRIMITIVES, "void"}:
                add("reference_signature", "The loader smoke-test profile accepts primitive parameters and returns")
            if program.details[key].traps:
                add("exception_dispatch", "Ordered CAP exception handler dispatch is not implemented")
            for feature in set(program.details[key].required_backend_features) - CHECKED_FEATURES:
                add("backend_feature", f"Execution feature not enabled: {feature}")
            for block in method.blocks:
                for stmt in block.statements:
                    label = stmt.label
                    if type(stmt).__name__ not in STATEMENTS:
                        add("statement", f"Unsupported statement: {type(stmt).__name__}", label)
                    if type(stmt).__name__ == "LookupSwitchStmt" and type(stmt.key).__name__ != "SootLocal":
                        add("switch_operand", "angr switch requires a local key operand", label)
                    for node in walk(stmt):
                        name = type(node).__name__
                        if node is stmt or name in VALUES:
                            continue
                        if name == "SootBinopExpr":
                            if node.op not in SAFE_BINOPS or node.type != "int":
                                add("arithmetic", f"Unchecked arithmetic semantics: {node.op}<{node.type}>", label)
                        elif name == "SootConditionExpr":
                            if node.op not in {"eq", "ne", "lt", "le", "gt", "ge"} or any(
                                v.type not in PRIMITIVES for v in (node.value1, node.value2)
                            ):
                                add("comparison", "Only signed primitive comparisons are enabled", label)
                        elif name == "SootCastExpr":
                            if node.cast_type not in PRIMITIVES or node.value.type not in PRIMITIVES:
                                add("reference_cast", "Reference casts need a class hierarchy and exception model", label)
                            elif node.cast_type == "boolean":
                                add("boolean_cast", "Numeric-to-boolean conversion is not defined by this profile", label)
                            elif type(node.value).__name__ != "SootLocal":
                                add("cast_operand", "angr primitive cast requires a local operand", label)
                        elif name == "SootStaticInvokeExpr":
                            signature = (node.class_name, node.method_name, tuple(node.method_params))
                            target = index.by_signature.get(signature)
                            if target is None:
                                add("external_call", f"Missing method/API model: {node.class_name}.{node.method_name}{node.method_params}", label)
                            elif "STATIC" not in program.methods[target].attrs:
                                add("call_kind", f"Static invocation targets instance method {target}", label)
                            else:
                                calls.add(target)
                        elif name.endswith("InvokeExpr"):
                            add("instance_call", "Instance dispatch and Java Card API models are a later stage", label)
                        else:
                            add("expression", f"Execution model not enabled for {name}", label)
            # angr automatically invokes <clinit> on a static call. Do not allow
            # its independent stock engine to execute code outside this profile.
            cls = program.classes[method.class_name]
            if any(m.name == "<clinit>" for m in cls.methods):
                add("class_initialization", f"Initializer of {cls.name} is not modeled")
            self.local_issues[key] = tuple(sorted(issues))
            self.calls[key] = tuple(sorted(calls))

    def reachable(self, key):
        self.index.method(key)
        visited, todo = set(), [key]
        while todo:
            current = todo.pop()
            if current in visited:
                continue
            visited.add(current)
            todo.extend(self.calls[current])
        return tuple(sorted(visited))

    def issues(self, key):
        return tuple(sorted({issue for k in self.reachable(key) for issue in self.local_issues[k]}))

    def require(self, key):
        issues = self.issues(key)
        if issues:
            detail = "\n".join(f"  {i.method_key} label {i.unit_label}: {i.message}" for i in issues)
            raise ExecutionNotReady(f"Method {key} was loaded, but is not ready for execution:\n{detail}")

