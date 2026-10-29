"""jvm_like_ir -> explicit Jimple units, without an operand stack or phi nodes."""
from __future__ import annotations

from dataclasses import replace

from .input import LoweringError, kind, op_name, read_method, stack_kind, terminator_kind
from .model import Block, Expr, Local, Method, Program, Trap, Unit, Value
from .symbols import SymbolTable

NUMERIC = {"byte", "short", "boolean", "int"}
RELATIONS = {"eq", "ne", "lt", "le", "gt", "ge"}
BINARY = {"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"}


class SootIRBuilder:
    def __init__(self, symbols: SymbolTable):
        self.symbols = symbols

    def build(self, method):
        return self.build_program([method]).methods[0]

    def build_program(self, methods):
        inputs = [read_method(m) for m in methods]
        if not inputs:
            raise LoweringError("No jvm_like_ir methods supplied")
        # Registrations are per build; configuration is reusable and is never mutated.
        config = self.symbols
        symbols = SymbolTable(config.package_aid, config.package_version, config.imports,
                              dict(config.class_names), dict(config.method_names),
                              dict(config.field_names), dict(config.catch_types))
        registered = [symbols.register(m) for m in inputs]
        bodies = tuple(_MethodBuilder(symbols, m, symbol).build() for m, symbol in zip(inputs, registered))
        return Program(bodies, tuple(sorted(symbols.unresolved)))


class _MethodBuilder:
    def __init__(self, symbols, source, symbol):
        self.symbols, self.source, self.symbol = symbols, source, symbol
        self.units, self.locals, self.marks, self.traps = [], {}, {}, []
        self.values = {}
        self.counter = 0
        self.offset = self.block_id = self.statement_id = None
        self.handlers = ()
        self.blocks = {b["id"]: b for b in source["blocks"]}
        self.block_order = [b["id"] for b in source["blocks"]]
        self.edges = list(source["edges"])
        self.edge_destinations = {}
        self.bridge_jobs = []
        self.source_map = {}
        self.slot_reference_types = {}
        self.value_reference_types = {}

    def error(self, message):
        raise LoweringError(f"{self.source['name']} B{self.block_id} @{self.offset}: {message}")

    def mark(self, name):
        if name in self.marks:
            self.error(f"Duplicate label {name}")
        self.marks[name] = len(self.units)

    def fresh(self, prefix="t", type_="int"):
        self.counter += 1
        return self.local(f"{prefix}{self.counter}", type_)

    def fresh_mark(self):
        self.counter += 1
        return f"generated_{self.counter}"

    def local(self, name, type_):
        if name in self.locals and self.locals[name] != type_:
            self.error(f"Conflicting local types for {name}")
        self.locals[name] = type_
        return Value("local", type_, name=name)

    @staticmethod
    def constant(value, type_="int"):
        return Value("constant", type_, value=value)

    def emit(self, kind_, **kwargs):
        self.units.append(Unit(len(self.units), kind_, self.offset, self.block_id,
                               self.statement_id, handlers=self.handlers, **kwargs))

    def assign(self, right, target=None):
        target = target or self.fresh(type_=right.type)
        self.emit("assign", left=target, right=right)
        return target

    def cast(self, value, type_):
        if value.type == type_:
            return value
        if value.kind == "constant" and value.value is None and type_ not in NUMERIC:
            return self.assign(value, self.fresh(type_=type_))
        # The inspected angr Cast handler reads a local from memory. Keep casts
        # on locals even when the input IR supplies a constant immediate.
        if value.kind != "local":
            value = self.assign(value)
        return self.assign(Expr("cast", type_, (value,)))

    def int_value(self, value):
        if value.type not in NUMERIC:
            self.error(f"Expected numeric value, got {value.type}")
        return self.cast(value, "int")

    def narrow(self, value, type_="short"):
        return self.int_value(self.cast(value, type_))

    def declared(self, value, type_):
        if type_ == "boolean":
            if value.type == "boolean":
                return value
            if value.kind == "constant" and value.value in (0, 1):
                return self.constant(value.value, "boolean")
            # A JVM boolean is not an arbitrary integer. Do not invent a conversion.
            self.error("Dynamic short -> boolean requires a proven 0/1 value; unsupported in this version")
        return self.cast(value, type_)

    def slot(self, index, source_type):
        sk = stack_kind(source_type)
        if type(index) is not int or index < 0 or index + (2 if sk == "int" else 1) > self.source["local_slot_count"]:
            self.error(f"Invalid local slot {index}")
        return self.local(f"l{index}_{sk}", self.slot_reference_types.get(index, "java.lang.Object") if sk == "reference" else "int")

    def operand(self, operand):
        if "name" in operand:
            key = (self.block_id, operand["name"])
            if key not in self.values:
                self.error(f"Undefined or cross-block value {operand['name']}; use a block parameter")
            return self.values[key]
        if "value" not in operand:
            self.error(f"Malformed operand {operand!r}")
        sk, value = stack_kind(operand["type"]), operand["value"]
        if sk == "reference":
            if value is not None:
                self.error("Only null reference constants are supported")
            return self.constant(None, "null")
        if type(value) is not int:
            self.error("Integer constant required")
        bits = 16 if sk == "short" else 32
        if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
            self.error(f"Constant {value} is outside signed {bits}-bit range")
        return self.constant(value)

    def result(self, stmt, value):
        result = stmt.get("result")
        if result is None:
            self.error(f"{stmt['op']} requires a result")
        key = (self.block_id, result["name"])
        if key in self.values:
            self.error(f"Duplicate value definition {result['name']}")
        sk = stack_kind(result["type"])
        if (value.type in NUMERIC) != (sk != "reference"):
            self.error(f"Result type mismatch for {result['name']}")
        self.values[key] = value

    def finish_numeric(self, stmt, value):
        sk = stack_kind(stmt["result"]["type"])
        if sk not in ("short", "int"):
            self.error("Numeric result required")
        self.result(stmt, self.narrow(value) if sk == "short" else self.int_value(value))

    def check_arity(self, stmt, operands, count, result):
        if len(operands) != count or (stmt.get("result") is not None) != result:
            self.error(f"{stmt['op']}: expected {count} operands, result={result}")

    def lower_statement(self, stmt):
        op = op_name(stmt)
        args = tuple(self.operand(o) for o in stmt.get("operands", []))
        semantic = stmt.get("semantic_type")
        mode = stmt.get("mode")
        if op == "load_local":
            self.check_arity(stmt, args, 0, True)
            self.result(stmt, self.assign(self.slot(stmt["local_index"], stmt["result"]["type"])))
        elif op == "store_local":
            self.check_arity(stmt, args, 1, False)
            if semantic is None:
                self.error("store_local needs semantic_type")
            target = self.slot(stmt["local_index"], semantic)
            self.assign(args[0], target)
        elif op in ("copy", "const"):
            self.check_arity(stmt, args, 1, True)
            self.result(stmt, args[0])
        elif op == "binary" or op in BINARY:
            self.check_arity(stmt, args, 2, True)
            operation = mode if op == "binary" else op
            if operation not in BINARY:
                self.error(f"Unsupported binary operation {operation}")
            left, right = map(self.int_value, args)
            if operation in ("shl", "shr", "ushr"):
                right = self.assign(Expr("binary", "int", (right, self.constant(31)), "and"))
            raw = self.assign(Expr("binary", "int", (left, right), operation))
            self.finish_numeric(stmt, raw)
        elif op in ("unary", "neg"):
            self.check_arity(stmt, args, 1, True)
            if op == "unary" and mode != "neg":
                self.error(f"Unsupported unary operation {mode}")
            self.finish_numeric(stmt, self.assign(Expr("unary", "int", (self.int_value(args[0]),), "neg")))
        elif op == "checkcast":
            self.check_arity(stmt, args, 1, True)
            target = self.symbols.type_name(semantic)
            if target in NUMERIC or target == "void":
                self.error("checkcast requires a reference target")
            self.result(stmt, self.cast(args[0], target))
        elif op in ("convert", "cast"):
            self.check_arity(stmt, args, 1, True)
            target = kind(semantic) if semantic else {"s2b": "byte", "i2b": "byte", "i2s": "short", "s2i": "int"}.get(mode)
            if target not in ("byte", "short", "int"):
                self.error(f"Unsupported numeric conversion {mode}/{target}")
            value = self.int_value(args[0])
            self.result(stmt, self.narrow(value, target) if target != "int" else value)
        elif op in ("compare", "cmp"):
            self.check_arity(stmt, args, 2, True)
            if mode not in (None, "signed"):
                self.error("Only signed integer compare is supported")
            left, right = map(self.int_value, args)
            result = self.fresh()
            less, greater, done = self.fresh_mark(), self.fresh_mark(), self.fresh_mark()
            self.emit("if", right=Expr("condition", "boolean", (left, right), "lt"), target=less)
            self.emit("if", right=Expr("condition", "boolean", (left, right), "gt"), target=greater)
            self.assign(self.constant(0), result)
            self.emit("goto", target=done)
            self.mark(less)
            self.assign(self.constant(-1), result)
            self.emit("goto", target=done)
            self.mark(greater)
            self.assign(self.constant(1), result)
            self.mark(done)
            self.result(stmt, result)
        elif op in ("load_field", "store_field"):
            ref = self.symbols.field_ref(stmt["reference"], mode)
            receivers = 0 if ref.is_static else 1
            self.check_arity(stmt, args, receivers + (op == "store_field"), op == "load_field")
            base = () if ref.is_static else (self.cast(args[0], ref.owner),)
            field = Expr("field", ref.type, base, field=ref)
            if op == "load_field":
                value = self.assign(field)
                self.result(stmt, self.int_value(value) if ref.type in NUMERIC else value)
            else:
                self.assign(self.declared(args[-1], ref.type), field)
        elif op in ("array_load", "array_store"):
            self.check_arity(stmt, args, 2 if op == "array_load" else 3, op == "array_load")
            if semantic is None:
                self.error("Array operation needs semantic_type")
            element = self.symbols.type_name(semantic)
            if element == "byte" and args[0].type == "boolean[]":
                element = "boolean"  # baload/bastore serve both array kinds
            if element == "void" or element.endswith("[]"):
                self.error("Expected array element type")
            base = self.cast(args[0], element + "[]")
            index = self.int_value(args[1])
            array = Expr("array", element, (base, index))
            if op == "array_load":
                value = self.assign(array)
                self.result(stmt, self.int_value(value) if element in NUMERIC else value)
            else:
                self.assign(self.declared(args[2], element), array)
        elif op == "array_length":
            self.check_arity(stmt, args, 1, True)
            # lengthof is defined for any array; Object[] is not a supertype of byte[].
            # Keep a dedicated type obligation for the adapter instead of a wrong cast.
            if not args[0].type.endswith("[]"):
                self.error("array_length needs a precise array type; mixed Object/array slots are not supported yet")
            self.finish_numeric(stmt, self.assign(Expr("length", "int", args)))
        elif op == "new_object":
            self.check_arity(stmt, args, 0, True)
            type_ = self.symbols.reference_class(stmt["reference"])
            self.result(stmt, self.assign(Expr("new", type_)))
        elif op == "new_array":
            self.check_arity(stmt, args, 1, True)
            type_ = self.symbols.type_name(semantic) if semantic else None
            if not type_ or not type_.endswith("[]"):
                self.error("new_array needs array semantic_type")
            self.result(stmt, self.assign(Expr("new_array", type_, (self.int_value(args[0]),))))
        elif op == "call":
            mode = {"invokevirtual": "virtual", "invokespecial": "special", "invokestatic": "static", "invokeinterface": "interface"}.get(mode, mode)
            if mode not in ("virtual", "special", "static", "interface"):
                self.error(f"Unknown invocation mode {mode}")
            ref = self.symbols.method_ref(stmt["reference"], mode)
            nreceiver = 0 if ref.is_static else 1
            self.check_arity(stmt, args, len(ref.params) + nreceiver, ref.returns != "void")
            call_args = (() if ref.is_static else (self.cast(args[0], ref.owner),)) + tuple(self.declared(v, t) for v, t in zip(args[nreceiver:], ref.params))
            invoke = Expr("invoke", ref.returns, call_args, method=ref, mode=mode)
            if ref.returns == "void":
                self.emit("invoke", right=invoke)
            else:
                value = self.assign(invoke)
                self.result(stmt, self.int_value(value) if ref.returns in NUMERIC else value)
        else:
            self.error(f"Unsupported operation: {op!r}")

    def prepare_parameters(self):
        for block in self.source["blocks"]:
            for i, p in enumerate(block["parameters"]):
                sk = stack_kind(p["type"])
                name = f"b{block['id']}_p{i}"
                type_ = self.value_reference_types.get((block["id"], p["name"]), "java.lang.Object") if sk == "reference" else "int"
                self.values[(block["id"], p["name"])] = self.local(name, type_)

    def prepare_edges(self):
        for index, edge in enumerate(self.edges):
            if edge["kind"] == "EXCEPTION":
                continue
            args = edge.get("arguments", [])
            target = self.blocks[edge["target"]]
            if len(args) != len(target["parameters"]):
                self.error("Edge argument count differs from block parameter count")
            if args:
                mark = f"edge_{index}"
                self.bridge_jobs.append((mark, edge))
            else:
                mark = f"block_{edge['target']}"
            self.edge_destinations[index] = mark

    def normal_edges(self, block):
        return [(i, e) for i, e in enumerate(self.edges) if e["source"] == block and e["kind"] != "EXCEPTION"]

    def lower_terminator(self, block):
        term = block["terminator"]
        self.offset, self.statement_id = term["offset"], "terminator"
        self.handlers = tuple(term.get("handler_indices", ()))
        args = tuple(self.operand(o) for o in term.get("operands", []))
        edges = self.normal_edges(block["id"])
        k = terminator_kind(term)
        if k == "branch":
            branches = {e["kind"]: self.edge_destinations[i] for i, e in edges}
            if len(edges) != 2 or set(branches) != {"CONDITIONAL_TRUE", "CONDITIONAL_FALSE"} or len(args) != 2 or term.get("relation") not in RELATIONS:
                self.error("branch requires two operands, a relation, and true/false edges")
            self.emit("if", right=Expr("condition", "boolean", args, term["relation"]), target=branches["CONDITIONAL_TRUE"])
            self.emit("goto", target=branches["CONDITIONAL_FALSE"])
        elif k == "goto":
            if len(edges) != 1 or args or edges[0][1]["kind"] not in ("GOTO", "FALLTHROUGH", "UNCONDITIONAL"):
                self.error("goto requires exactly one normal successor and no operands")
            self.emit("goto", target=self.edge_destinations[edges[0][0]])
        elif k == "switch":
            defaults = [self.edge_destinations[i] for i, e in edges if e["kind"] == "SWITCH_DEFAULT"]
            cases = [(e["case_value"], self.edge_destinations[i]) for i, e in edges if e["kind"] == "SWITCH_CASE"]
            if len(args) != 1 or len(defaults) != 1 or len(cases) != len(edges) - 1 or len({c for c, _ in cases}) != len(cases) or any(type(c) is not int for c, _ in cases):
                self.error("Malformed switch edges")
            self.emit("switch", right=self.int_value(args[0]), cases=tuple(sorted(cases)), default_target=defaults[0])
        elif k == "return":
            if edges or len(args) != (self.symbol.returns != "void"):
                self.error("return operands/edges disagree with method signature")
            self.emit("return" if args else "return_void", right=self.declared(args[0], self.symbol.returns) if args else None)
        elif k == "throw":
            if edges or len(args) != 1:
                self.error("throw requires one operand and no normal edges")
            self.emit("throw", right=self.cast(args[0], "java.lang.Throwable"))
        else:
            self.error(f"Unsupported terminator {k!r}")

    def prologue(self):
        self.mark("entry")
        parameter_index = 0
        for arg in self.source["arguments"]:
            declared = self.symbol.owner if arg["is_receiver"] else self.symbols.type_name(arg["declared_type"])
            value = self.fresh("arg", declared)
            rhs = Value("this" if arg["is_receiver"] else "parameter", declared, index=None if arg["is_receiver"] else parameter_index)
            self.emit("identity", left=value, right=rhs)
            if not arg["is_receiver"]:
                parameter_index += 1
            target = self.slot(arg["slot"], arg["declared_type"])
            self.assign(self.int_value(value) if declared in NUMERIC else value, target)
        self.emit("goto", target=f"block_{self.source['entry']}")

    def collect_traps(self, begin, handler_indices):
        for index in handler_indices:
            h = self.source["handlers"][index]
            self.traps.append(Trap(begin, len(self.units), f"handler_{index}",
                                   self.symbols.catch_type(h["catch_type_index"]), index, bool(h["stop_bit"])))

    def edge_bridges(self):
        self.handlers = ()
        self.offset = self.statement_id = None
        for mark, edge in self.bridge_jobs:
            self.block_id = edge["source"]
            self.mark(mark)
            parameters = self.blocks[edge["target"]]["parameters"]
            # Save ALL sources first: even a back-edge swap p0,p1 := p1,p0 is correct.
            sources = [self.assign(self.operand(a), self.fresh("edge", self.operand(a).type)) for a in edge["arguments"]]
            for parameter, value in zip(parameters, sources):
                self.assign(value, self.values[(edge["target"], parameter["name"])])
            self.emit("goto", target=f"block_{edge['target']}")

    def exception_bridges(self):
        self.handlers = ()
        self.offset = self.statement_id = self.block_id = None
        used = sorted({trap.priority for trap in self.traps})
        for index in used:
            h = self.source["handlers"][index]
            target_blocks = [b for b in self.source["blocks"] if b["start_offset"] == h["target"]]
            if len(target_blocks) != 1 or len(target_blocks[0]["parameters"]) != 1 or stack_kind(target_blocks[0]["parameters"][0]["type"]) != "reference":
                self.error("Exception handler must have exactly one reference block parameter")
            target = target_blocks[0]
            self.mark(f"handler_{index}")
            type_ = self.symbols.catch_type(h["catch_type_index"])
            caught = self.fresh("caught", type_)
            self.emit("identity", left=caught, right=Value("caught_exception", type_))
            self.assign(caught, self.values[(target["id"], target["parameters"][0]["name"])])
            self.emit("goto", target=f"block_{target['id']}")

    def build(self):
        from .source_validation import validate_source
        from .reference_types import infer_reference_types
        validate_source(self.source)
        self.slot_reference_types, self.value_reference_types = infer_reference_types(self.source, self.symbols, self.symbol.owner)
        self.prepare_parameters()
        self.prepare_edges()
        self.prologue()
        for block in self.source["blocks"]:
            self.block_id = block["id"]
            for offset in block.get("source_offsets", ()):
                self.source_map.setdefault(offset, [])
            self.mark(f"block_{block['id']}")
            for stmt in block["statements"]:
                self.offset, self.statement_id = stmt["offset"], str(stmt["id"])
                self.handlers = tuple(stmt.get("handler_indices", ()))
                begin = len(self.units)
                self.lower_statement(stmt)
                self.source_map.setdefault(self.offset, []).extend(range(begin, len(self.units)))
                if stmt.get("may_throw", False):
                    self.collect_traps(begin, self.handlers)
            begin = len(self.units)
            self.lower_terminator(block)
            self.source_map.setdefault(self.offset, []).extend(range(begin, len(self.units)))
            if terminator_kind(block["terminator"]) == "throw":
                self.collect_traps(begin, self.handlers)
        self.edge_bridges()
        self.exception_bridges()
        def resolve(label):
            if label not in self.marks:
                self.error(f"Unknown label {label}")
            return self.marks[label]
        units = tuple(replace(u, target=resolve(u.target) if u.target is not None else None,
                              cases=tuple((v, resolve(t)) for v, t in u.cases),
                              default_target=resolve(u.default_target) if u.default_target is not None else None) for u in self.units)
        traps = tuple(replace(t, handler=resolve(t.handler)) for t in self.traps)
        result = Method(self.source["name"], self.symbol,
                        tuple(Local(n, t) for n, t in self.locals.items()), units,
                        make_blocks(units, traps), traps,
                        tuple((off, tuple(labels)) for off, labels in sorted(self.source_map.items())),
                        tuple(self.source.get("warnings", ())),
                        backend_features(units, traps))
        result.validate()
        return result


def backend_features(units, traps):
    features = {"unit_label_targets"}
    for u in units:
        if u.kind == "throw" or traps:
            features.add("ordered_exception_dispatch")
        for expr in (u.left, u.right):
            if not isinstance(expr, Expr):
                continue
            if expr.kind == "binary":
                features.add("int32_wraparound")
                if expr.operator in ("div", "rem", "ushr"):
                    features.add({"div": "signed_division", "rem": "java_remainder", "ushr": "logical_right_shift"}[expr.operator])
            elif expr.kind == "condition" and expr.operator not in ("eq", "ne"):
                features.add("signed_int_comparisons")
            elif expr.kind == "cast":
                features.add("primitive_casts" if expr.type in NUMERIC else "reference_casts")
            elif expr.kind in ("array", "new_array", "length"):
                features.add("java_array_semantics")
            elif expr.kind == "invoke":
                features.add("java_calls_and_api_models")
    return tuple(sorted(features))


def make_blocks(units, traps):
    leaders = {0}
    terminal = {"goto", "if", "switch", "return", "return_void", "throw"}
    for unit in units:
        if unit.target is not None:
            leaders.add(unit.target)
        if unit.default_target is not None:
            leaders.add(unit.default_target)
        leaders.update(t for _, t in unit.cases)
        if unit.kind in terminal and unit.label + 1 < len(units):
            leaders.add(unit.label + 1)
    leaders.update(t.handler for t in traps)
    leaders = sorted(leaders)
    ranges = [tuple(range(start, end)) for start, end in zip(leaders, leaders[1:] + [len(units)])]
    owner = {label: index for index, labels in enumerate(ranges) for label in labels}
    result = []
    for index, labels in enumerate(ranges):
        last = units[labels[-1]]
        succ = []
        if last.kind in ("goto", "if"):
            succ.append(owner[last.target])
        if last.kind == "switch":
            succ.extend(owner[t] for _, t in last.cases)
            succ.append(owner[last.default_target])
        if last.kind not in ("goto", "switch", "return", "return_void", "throw"):
            if labels[-1] + 1 >= len(units):
                raise LoweringError("Method falls off its last unit")
            succ.append(owner[labels[-1] + 1])
        exceptional = [owner[t.handler] for t in sorted(traps, key=lambda t: t.priority) if t.begin <= labels[-1] and t.end > labels[0]]
        result.append(Block(index, labels[0], labels, tuple(dict.fromkeys(succ)), tuple(dict.fromkeys(exceptional))))
    return tuple(result)
