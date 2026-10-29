"""Conservative operation checks before executing with the CAP heap.

All adapted bodies can be loaded. Only this explicitly checked subset may be
executed. Heap guards additionally validate the concrete/symbolic state at run
time. API models are opt-in; general Java exception handlers remain unsupported.
"""
from dataclasses import asdict, dataclass, fields, is_dataclass

from .errors import ExecutionNotReady, HeapError
from .heap_types import HeapSchema, PRIMITIVES, is_reference_type, is_value_type
from .calls import CallResolver, invocation_mode


SUPPORTED_FEATURES = frozenset({
    "unit_label_targets", "int32_wraparound", "signed_int_comparisons", "primitive_casts",
    "java_array_semantics", "reference_casts", "cap_heap_objects", "cap_heap_instance_fields",
    "reference_arguments", "reference_equality",
    "java_remainder", "cap_virtual_dispatch",
})
# Calls are checked individually and transitively, not accepted as a feature wholesale.
CHECKED_FEATURES = SUPPORTED_FEATURES | {"java_calls_and_api_models"}
SAFE_BINOPS = frozenset({"add", "sub", "mul", "and", "or", "xor", "rem"})
STATEMENTS = frozenset({"IdentityStmt", "AssignStmt", "IfStmt", "GotoStmt",
                        "LookupSwitchStmt", "ReturnStmt", "ReturnVoidStmt", "InvokeStmt"})
VALUES = frozenset({"SootLocal", "SootIntConstant", "SootParamRef", "SootThisRef", "SootNullConstant"})


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
    def __init__(self, program, index, api=None):
        self.program, self.index = program, index
        self.api = api
        self.heap_schema = HeapSchema(program, () if api is None else api.classes)
        self.call_resolver = CallResolver(program, index, self.heap_schema, api)
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
            if any(not is_value_type(ty) for ty in method.params) or (method.ret != "void" and not is_value_type(method.ret)):
                add("signature_type", "Unsupported parameter/return type")
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
                    if type(stmt).__name__ == "AssignStmt" and type(stmt.right_op).__name__.endswith("InvokeExpr") and type(stmt.left_op).__name__ != "SootLocal":
                        add("call_target", "Invocation result must be assigned to a local", label)
                    for node in walk(stmt):
                        name = type(node).__name__
                        if node is stmt or name in VALUES:
                            continue
                        if name == "SootBinopExpr":
                            if node.op not in SAFE_BINOPS or node.type != "int":
                                add("arithmetic", f"Unchecked arithmetic semantics: {node.op}<{node.type}>", label)
                        elif name == "SootConditionExpr":
                            primitive = all(v.type in PRIMITIVES for v in (node.value1, node.value2))
                            reference = all(is_reference_type(v.type) for v in (node.value1, node.value2))
                            if not ((primitive and node.op in {"eq", "ne", "lt", "le", "gt", "ge"}) or
                                    (reference and node.op in {"eq", "ne"})):
                                add("comparison", "Expected primitive comparison or reference eq/ne", label)
                        elif name == "SootCastExpr":
                            if is_reference_type(node.cast_type) and is_reference_type(node.value.type):
                                pass  # Actual type and complete hierarchy are checked at runtime.
                            elif node.cast_type not in PRIMITIVES or node.value.type not in PRIMITIVES:
                                add("cast_type", "Cannot mix primitive and reference casts", label)
                            elif node.cast_type == "boolean":
                                add("boolean_cast", "Numeric-to-boolean conversion is not defined by this profile", label)
                            elif type(node.value).__name__ != "SootLocal":
                                add("cast_operand", "angr primitive cast requires a local operand", label)
                        elif name == "SootNewExpr":
                            try:
                                self.heap_schema.allocation_fields(node.type)
                            except HeapError as exc:
                                add(exc.code, str(exc), label)
                        elif name == "SootNewArrayExpr":
                            if not is_value_type(node.base_type) or node.size.type not in {"int", "short"}:
                                add("array_type", "Unsupported array element type/length", label)
                        elif name == "SootArrayRef":
                            if node.base.type != node.type + "[]" or node.index.type not in {"int", "short"}:
                                add("array_type", "Invalid array element or index type", label)
                        elif name == "SootLengthExpr":
                            if not node.value.type.endswith("[]"):
                                add("array_type", "Array length requires an array reference", label)
                        elif name == "SootInstanceFieldRef":
                            field, owner = node.field
                            try:
                                self.heap_schema.field(owner, field, node.type)
                            except HeapError as exc:
                                add(exc.code, str(exc), label)
                        elif invocation_mode(node):
                            try:
                                targets = self.call_resolver.potential_targets(node)
                                calls.update(t.key for t in targets if t.key is not None)
                            except HeapError as exc:
                                add(exc.code, str(exc), label)
                        elif name.endswith("InvokeExpr"):
                            add("instance_call", "Instance dispatch and Java Card API models are a later stage", label)
                        else:
                            add("expression", f"Execution model not enabled for {name}", label)
            # Class initialization is deliberately not delegated to stock angr.
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

