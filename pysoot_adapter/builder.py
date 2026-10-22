"""Translate soot_ir into genuine pysoot nodes without starting Java or angr."""
from __future__ import annotations

from soot_ir import Expr, Program, Value
from soot_ir.builder import backend_features

from .backend import load_backend
from .errors import AdapterError
from .metadata import ProgramMetadata
from .model import AdaptedProgram, MethodDetails


class PySootAdapter:
    def build(self, program: Program, metadata: ProgramMetadata) -> AdaptedProgram:
        return _ProgramBuilder(program, metadata).build()


class _ProgramBuilder:
    def __init__(self, program, metadata):
        if not isinstance(program, Program) or not isinstance(metadata, ProgramMetadata):
            raise AdapterError("Expected soot_ir.Program and ProgramMetadata")
        if program.schema != "cap2soot.soot_ir.program/1":
            raise AdapterError(f"Unsupported program schema {program.schema}")
        self.program, self.metadata = program, metadata
        self.backend = load_backend()
        self.classes, self.declarations, self.aliases, self.fields = {}, {}, {}, {}
        self.external_methods, self.external_fields = {}, {}
        self.unresolved = set(program.unresolved_symbols) | set(metadata.unresolved_symbols)
        self.current = ""
        for cls in metadata.classes:
            if cls.name in self.classes:
                raise AdapterError(f"Duplicate class {cls.name}")
            self.classes[cls.name] = cls
            field_names = set()
            for field in cls.fields:
                if field.key in self.fields or field.name in field_names:
                    raise AdapterError(f"Duplicate field in {cls.name}: {field.name}")
                field_names.add(field.name)
                self.fields[field.key] = (cls.name, field)
            signatures = set()
            for method in cls.methods:
                signature = (method.name, method.params)
                if method.key in self.declarations or signature in signatures:
                    raise AdapterError(f"Duplicate method in {cls.name}: {method.key}")
                if "CONSTRUCTOR" in method.attrs and (
                    method.name != "<init>" or method.returns != "void" or
                    {"STATIC", "ABSTRACT"}.intersection(method.attrs)
                ):
                    raise AdapterError(f"Invalid constructor declaration {method.key}")
                signatures.add(signature)
                self.declarations[method.key] = (cls.name, method)
                for key in (method.key, *method.aliases):
                    if key in self.aliases and self.aliases[key] != method.key:
                        raise AdapterError(f"Conflicting method alias {key}")
                    self.aliases[key] = method.key
        if not self.classes:
            raise AdapterError("Class declarations are required")
        self.unresolved.difference_update(self.aliases)

    def error(self, message):
        raise AdapterError(f"{self.current}: {message}")

    def method_ref(self, ref, mode):
        key = self.aliases.get(ref.key)
        if key is not None:
            owner, decl = self.declarations[key]
            if (ref.params, ref.returns, ref.is_static) != (decl.params, decl.returns, "STATIC" in decl.attrs):
                self.error(f"Internal call signature disagrees with {key}")
            name = decl.name
        else:
            if ref.owner in self.classes:
                self.error(f"Missing internal method declaration/binding: {ref.key}")
            owner, name = ref.owner, ref.name
            previous = self.external_methods.setdefault(ref.key, ref)
            if previous != ref:
                self.error(f"Conflicting external method {ref.key}")
            if not ref.resolved:
                self.unresolved.add(ref.key)
        if (mode == "static") != ref.is_static or (name == "<init>" and mode != "special"):
            self.error(f"Invalid invocation mode for {ref.signature}")
        return owner, name

    def field_ref(self, ref):
        declaration = self.fields.get(ref.key)
        if declaration is not None:
            owner, field = declaration
            if (ref.owner, ref.type, ref.is_static) != (owner, field.type, "STATIC" in field.attrs):
                self.error(f"Field descriptor disagreement for {ref.key}")
            return field.name, owner  # pysoot uses (name, declaring class).
        if ref.owner in self.classes:
            self.error(f"Missing internal field declaration/binding: {ref.key}")
        previous = self.external_fields.setdefault(ref.key, ref)
        if previous != ref:
            self.error(f"Conflicting external field {ref.key}")
        if not ref.resolved:
            self.unresolved.add(ref.key)
        return ref.name, ref.owner

    def value(self, value, locals_):
        b = self.backend
        if isinstance(value, Value):
            if value.kind == "local":
                return locals_[value.name]
            if value.kind == "constant":
                if value.value is None:
                    if value.type in {"int", "short", "byte", "boolean", "void"}:
                        self.error("Null constant has a primitive type")
                    return b.SootNullConstant(value.type)
                if type(value.value) is not int or value.type not in {"int", "short", "byte", "boolean"}:
                    self.error("Unsupported constant")
                return b.SootIntConstant(value.type, value.value)
            if value.kind == "this":
                if self.source.symbol.is_static or value.type != self.source.symbol.owner:
                    self.error("Invalid @this identity")
                return b.SootThisRef(value.type)
            if value.kind == "parameter":
                params = self.source.symbol.params
                if (type(value.index) is not int or not 0 <= value.index < len(params)
                        or value.type != params[value.index]):
                    self.error("Invalid @parameter identity")
                return b.SootParamRef(value.type, value.index)
            if value.kind == "caught_exception":
                return b.SootCaughtExceptionRef(value.type)
            self.error(f"Unsupported value {value.kind}")
        if not isinstance(value, Expr):
            self.error("Expected expression or value")
        args = tuple(self.value(v, locals_) for v in value.operands)
        kind = value.kind
        expected = {"binary": 2, "condition": 2, "unary": 1, "cast": 1, "length": 1,
                    "array": 2, "new": 0, "new_array": 1}
        if kind in expected and len(args) != expected[kind]:
            self.error(f"Invalid {kind} expression arity")
        if kind == "binary":
            if value.operator not in {"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"}:
                self.error(f"Unsupported binary operation {value.operator}")
            return b.SootBinopExpr(value.type, value.operator, *args)
        if kind == "condition":
            if value.operator not in {"eq", "ne", "lt", "le", "gt", "ge"}:
                self.error(f"Unsupported condition {value.operator}")
            return b.SootConditionExpr(value.type, value.operator, *args)
        if kind == "unary":
            if value.operator != "neg":
                self.error(f"Unsupported unary operation {value.operator}")
            return b.SootUnopExpr(value.type, value.operator, args[0])
        if kind == "cast":
            return b.SootCastExpr(value.type, value.type, args[0])
        if kind == "length":
            return b.SootLengthExpr(value.type, args[0])
        if kind == "array":
            return b.SootArrayRef(value.type, *args)
        if kind == "new":
            return b.SootNewExpr(value.type, value.type)
        if kind == "new_array":
            if not value.type.endswith("[]"):
                self.error("new_array requires an array type")
            return b.SootNewArrayExpr(value.type, value.type[:-2], args[0])
        if kind == "field":
            ref = self.field_ref(value.field)
            return (b.SootStaticFieldRef(value.type, ref) if value.field.is_static else
                    b.SootInstanceFieldRef(value.type, args[0], ref))
        if kind == "invoke":
            owner, name = self.method_ref(value.method, value.mode)
            invoke_classes = {"static": b.SootStaticInvokeExpr, "virtual": b.SootVirtualInvokeExpr,
                              "special": b.SootSpecialInvokeExpr, "interface": b.SootInterfaceInvokeExpr}
            receiver = {} if value.mode == "static" else {"base": args[0]}
            actual_args = args if value.mode == "static" else args[1:]
            return invoke_classes[value.mode](type=value.type, class_name=owner, method_name=name,
                                              method_params=value.method.params, args=actual_args, **receiver)
        self.error(f"Unsupported expression {kind}")

    def statement(self, unit, locals_):
        b = self.backend
        # -1 identifies synthesized nodes; retain exact None in details.
        common = {"label": unit.label, "offset": unit.offset if unit.offset is not None else -1}
        rhs = self.value(unit.right, locals_) if unit.right is not None else None
        if unit.kind in {"assign", "identity"}:
            cls = b.AssignStmt if unit.kind == "assign" else b.IdentityStmt
            return cls(**common, left_op=self.value(unit.left, locals_), right_op=rhs)
        if unit.kind == "if":
            return b.IfStmt(**common, condition=rhs, target=unit.target)
        if unit.kind == "goto":
            return b.GotoStmt(**common, target=unit.target)
        if unit.kind == "switch":
            cases = dict(unit.cases)
            if len(cases) != len(unit.cases):
                self.error(f"Duplicate switch key at Unit {unit.label}")
            return b.LookupSwitchStmt(**common, key=rhs, lookup_values_and_targets=b.frozendict(cases),
                                      default_target=unit.default_target)
        if unit.kind == "invoke":
            return b.InvokeStmt(**common, invoke_expr=rhs)
        if unit.kind == "return":
            return b.ReturnStmt(**common, value=rhs)
        if unit.kind == "return_void":
            return b.ReturnVoidStmt(**common)
        if unit.kind == "throw":
            return b.ThrowStmt(**common, obj=rhs)
        self.error(f"Unsupported statement {unit.kind}")

    def convert_method(self, source, owner, declaration):
        b = self.backend
        self.current = source.source_name
        self.source = source
        if source.schema != "cap2soot.soot_ir.method/1":
            self.error(f"Unsupported method schema {source.schema}")
        source.validate()
        if "ABSTRACT" in declaration.attrs:
            self.error("Abstract method must not have a body")
        if (source.symbol.owner, source.symbol.params, source.symbol.returns, source.symbol.is_static) != (
            owner, declaration.params, declaration.returns, "STATIC" in declaration.attrs
        ):
            self.error("Method body disagrees with CAP declaration")
        locals_ = {v.name: b.SootLocal(v.type, v.name) for v in source.locals}
        statements = tuple(self.statement(unit, locals_) for unit in source.units)
        blocks = tuple(b.SootBlock(block.label, tuple(statements[i] for i in block.unit_labels), block.index)
                       for block in source.blocks)
        cfg, exceptional_preds = {}, {block: [] for block in blocks}
        for block in source.blocks:
            # pysoot's ExceptionalBlockGraph.getSuccs() includes BOTH edge kinds.
            successors = tuple(dict.fromkeys((*block.successors, *block.exceptional_successors)))
            if successors:
                cfg[blocks[block.index]] = tuple(blocks[i] for i in successors)
            for target in block.exceptional_successors:
                exceptional_preds[blocks[target]].append(blocks[block.index])
        method = b.SootMethod(owner, declaration.name, declaration.returns, declaration.attrs,
                              declaration.exceptions, blocks, declaration.params, b.frozendict(cfg),
                              b.frozendict({k: tuple(v) for k, v in exceptional_preds.items() if v}))
        details = MethodDetails(source.source_name, source.locals, source.traps, source.source_map,
                                tuple((u.label, u.offset, u.source_block, u.source_statement, u.handlers) for u in source.units),
                                tuple((bl.index, bl.successors) for bl in source.blocks),
                                tuple(sorted(set(source.required_backend_features) |
                                             set(backend_features(source.units, source.traps)))), source.warnings)
        return method, details

    def build(self):
        b = self.backend
        methods, details = {}, {}
        for source in self.program.methods:
            key = source.symbol.key
            if key in methods or key not in self.declarations:
                raise AdapterError(f"Missing or duplicate method declaration: {key}")
            methods[key], details[key] = self.convert_method(source, *self.declarations[key])
        for key, (owner, decl) in self.declarations.items():
            if key in methods:
                continue
            if "ABSTRACT" not in decl.attrs:
                raise AdapterError(f"Concrete method body missing: {key}")
            methods[key] = b.SootMethod(owner, decl.name, decl.returns, decl.attrs, decl.exceptions,
                                        (), decl.params, b.frozendict(), b.frozendict())
            details[key] = MethodDetails(key, (), (), (), (), (), (), ())
        for applet in self.metadata.applets:
            method = methods.get(applet.install_method_key)
            if method is None or "STATIC" not in method.attrs:
                raise AdapterError(f"Missing/static install method expected for applet {applet.aid}")
        classes = {
            c.name: b.SootClass(c.name, c.super_class, c.interfaces, c.attrs,
                                tuple(methods[d.key] for d in c.methods),
                                b.frozendict({f.name: (f.attrs, f.type) for f in c.fields}))
            for c in self.metadata.classes
        }
        referenced_types = set()
        for c in self.metadata.classes:
            referenced_types.update((c.super_class, *c.interfaces, *(f.type for f in c.fields)))
        for m in methods.values():
            referenced_types.update((m.class_name, m.ret, *m.params, *m.exceptions))
        for d in details.values():
            referenced_types.update(v.type for v in d.locals)
            referenced_types.update(t.exception_type for t in d.traps)
        for ref in self.external_methods.values():
            referenced_types.update((ref.owner, ref.returns, *ref.params))
        for ref in self.external_fields.values():
            referenced_types.update((ref.owner, ref.type))
        referenced_types = {t.removesuffix("[]") for t in referenced_types}
        external_classes = referenced_types - set(classes) - {"", "void", "boolean", "byte", "short", "int", "null"}
        return AdaptedProgram(b.frozendict(classes), b.frozendict(methods), b.frozendict(details), self.metadata,
                              tuple(self.external_methods[k] for k in sorted(self.external_methods)),
                              tuple(self.external_fields[k] for k in sorted(self.external_fields)),
                              tuple(sorted(external_classes)), tuple(sorted(self.unresolved)),
                              b.version, b.target_revision)
