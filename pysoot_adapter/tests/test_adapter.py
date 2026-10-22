"""Integration and behavioral tests using the installed, real pysoot classes."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from soot_ir import Expr, FieldRef, Local, Method, MethodRef, Program, Trap, Unit, Value
from soot_ir.builder import make_blocks
from pysoot_adapter import (
    AdapterError, ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata,
    PySootAdapter, metadata_from_cap,
)
from pysoot_adapter.backend import load_backend


OWNER = "example.Applet"


def local(name, type_="int"):
    return Value("local", type_, name=name)


def constant(value, type_="int"):
    return Value("constant", type_, value=value)


def body(units, locals_=(), *, key="method", name="method", params=(), returns="int", static=True, traps=()):
    return Method(name, MethodRef(key, OWNER, name, params, returns, static),
                  tuple(Local(v.name, v.type) for v in locals_), tuple(units),
                  make_blocks(units, traps), tuple(traps),
                  tuple((u.offset, (u.label,)) for u in units if u.offset is not None))


def declarations(*methods, fields=()):
    return ProgramMetadata((ClassMetadata(OWNER, "java.lang.Object", attrs=("PUBLIC",), fields=tuple(fields), methods=tuple(
        MethodMetadata(m.symbol.key, m.symbol.name, m.symbol.params, m.symbol.returns,
                       ("PUBLIC", "STATIC") if m.symbol.is_static else ("PUBLIC",))
        for m in methods
    )),))


def adapt(*methods, metadata=None, unresolved=()):
    return PySootAdapter().build(Program(tuple(methods), tuple(unresolved)), metadata or declarations(*methods))


def run_numeric(method, args):
    """Independent concrete oracle for control-flow/cast tests; NOT angr."""
    memory = {}
    statements = {s.label: s for b in method.blocks for s in b.statements}

    def signed(x, bits):
        x &= (1 << bits) - 1
        return x - (1 << bits) if x & (1 << (bits - 1)) else x

    def value(v):
        name = type(v).__name__
        if name == "SootLocal":
            return memory[v.name]
        if name == "SootIntConstant":
            return v.value
        if name == "SootParamRef":
            return args[v.index]
        if name == "SootCastExpr":
            return signed(value(v.value), {"byte": 8, "short": 16, "int": 32}[v.cast_type])
        if name == "SootBinopExpr":
            x, y = value(v.value1), value(v.value2)
            if v.op == "add":
                return signed(x + y, 32)
            raise AssertionError(v.op)
        if name == "SootConditionExpr":
            x, y = value(v.value1), value(v.value2)
            return {"lt": x < y, "ge": x >= y, "eq": x == y, "ne": x != y}[v.op]
        raise AssertionError(name)

    pc = 0
    for _ in range(100):
        stmt = statements[pc]
        name = type(stmt).__name__
        if name in {"IdentityStmt", "AssignStmt"}:
            memory[stmt.left_op.name] = value(stmt.right_op)
        elif name == "IfStmt" and value(stmt.condition):
            pc = stmt.target
            continue
        elif name == "GotoStmt":
            pc = stmt.target
            continue
        elif name == "LookupSwitchStmt":
            pc = stmt.lookup_values_and_targets.get(value(stmt.key), stmt.default_target)
            continue
        elif name == "ReturnStmt":
            return value(stmt.value)
        pc += 1
    raise AssertionError("Numeric test did not terminate")


class AdapterTests(unittest.TestCase):
    def test_real_nodes_branch_targets_are_unit_labels_not_block_indices(self):
        x, y = local("x"), local("y")
        source = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "if", 0, 0, right=Expr("condition", "boolean", (x, constant(0)), "lt"), target=4),
            Unit(2, "assign", 2, 1, left=y, right=constant(7)),
            Unit(3, "goto", 3, 1, target=5),
            Unit(4, "assign", 4, 2, left=y, right=constant(-7)),
            Unit(5, "return", 5, 3, right=y),
        ], (x, y), params=("int",))
        result = adapt(source)
        method = result.methods["method"]
        from pysoot.sootir.soot_method import SootMethod
        from pysoot.sootir.soot_statement import IfStmt
        self.assertIsInstance(method, SootMethod)
        branch = method.blocks[0].statements[-1]
        self.assertIsInstance(branch, IfStmt)
        self.assertEqual(branch.target, 4)
        self.assertNotEqual(method.block_by_label[branch.target].idx, branch.target)
        self.assertEqual([run_numeric(method, [v]) for v in (-2, 0, 2)], [-7, 7, 7])
        self.assertEqual(method.blocks[0].statements[0].offset, -1)
        self.assertIsNone(result.details["method"].unit_origins[0][1])

    def test_short_wraparound_preserved_by_cast_sequence(self):
        x, y, short = local("x"), local("y"), local("n", "short")
        source = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "assign", 0, 0, left=y, right=Expr("binary", "int", (x, constant(1)), "add")),
            Unit(2, "assign", 1, 0, left=short, right=Expr("cast", "short", (y,))),
            Unit(3, "assign", 2, 0, left=y, right=Expr("cast", "int", (short,))),
            Unit(4, "return", 3, 0, right=y),
        ], (x, y, short), params=("int",))
        result = adapt(source)
        self.assertEqual(run_numeric(result.methods["method"], [32767]), -32768)
        self.assertEqual(run_numeric(result.methods["method"], [-1]), 0)
        with self.assertRaisesRegex(AdapterError, "primitive_casts"):
            result.require_backend_features({"unit_label_targets"})

    def test_switch_shared_targets_and_default(self):
        x = local("x")
        source = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "switch", 0, 0, right=x, cases=((-1, 2), (7, 2)), default_target=3),
            Unit(2, "return", 3, 1, right=constant(10)),
            Unit(3, "return", 5, 2, right=constant(20)),
        ], (x,), params=("int",))
        method = adapt(source).methods["method"]
        self.assertEqual([run_numeric(method, [v]) for v in (-1, 7, 0)], [10, 10, 20])

    def test_constructor_calls_and_definition_are_renamed_together(self):
        receiver = local("r", OWNER)
        constructor = body([
            Unit(0, "identity", None, None, left=receiver, right=Value("this", OWNER)),
            Unit(1, "return_void", 0, 0),
        ], (receiver,), key="init", name="method_15", static=False, returns="void")
        caller = body([
            Unit(0, "assign", 0, 0, left=receiver, right=Expr("new", OWNER)),
            Unit(1, "invoke", 3, 0, right=Expr("invoke", "void", (receiver,), method=constructor.symbol, mode="special")),
            Unit(2, "return_void", 6, 0),
        ], (receiver,), key="install", returns="void")
        meta = declarations(caller, constructor)
        cls = meta.classes[0]
        init = replace(cls.methods[1], name="<init>", attrs=("PROTECTED", "CONSTRUCTOR"))
        meta = replace(meta, classes=(replace(cls, methods=(cls.methods[0], init)),))
        result = adapt(caller, constructor, metadata=meta)
        invocation = result.methods["install"].blocks[0].statements[1].invoke_expr
        self.assertEqual(result.methods["init"].name, "<init>")
        self.assertEqual(invocation.method_name, "<init>")
        self.assertEqual(invocation.base.name, "r")
        self.assertEqual(invocation.args, ())

    def test_internal_virtual_alias_resolves_to_declared_method(self):
        receiver = local("r", OWNER)
        callee = body([Unit(0, "return_void", 0, 0)], key="offset:10", returns="void", static=False)
        ref = replace(callee.symbol, key="token:4", name="method_t3_4", resolved=False)
        caller = body([
            Unit(0, "identity", None, None, left=receiver, right=Value("this", OWNER)),
            Unit(1, "invoke", 0, 0, right=Expr("invoke", "void", (receiver,), method=ref, mode="virtual")),
            Unit(2, "return_void", 3, 0),
        ], (receiver,), key="caller", name="caller", returns="void", static=False)
        meta = declarations(caller, callee)
        cls = meta.classes[0]
        meta = replace(meta, classes=(replace(cls, methods=(cls.methods[0], replace(cls.methods[1], aliases=("token:4",)))),))
        result = adapt(caller, callee, metadata=meta, unresolved=("token:4",))
        self.assertEqual(result.unresolved_symbols, ())
        self.assertEqual(result.methods["caller"].blocks[0].statements[1].invoke_expr.method_name, callee.symbol.name)

    def test_fields_use_name_then_owner_and_reuse_receiver_local(self):
        receiver, value = local("r", OWNER), local("v", "short")
        ref = FieldRef("field", OWNER, "balance", "short", False)
        source = body([
            Unit(0, "identity", None, None, left=receiver, right=Value("this", OWNER)),
            Unit(1, "assign", 0, 0, left=value, right=Expr("field", "short", (receiver,), field=ref)),
            Unit(2, "assign", 2, 0, left=Expr("field", "short", (receiver,), field=ref), right=value),
            Unit(3, "return", 4, 0, right=value),
        ], (receiver, value), returns="short", static=False)
        result = adapt(source, metadata=declarations(source, fields=(FieldMetadata("field", "balance", "short"),)))
        statements = result.methods["method"].blocks[0].statements
        self.assertEqual(statements[1].right_op.field, ("balance", OWNER))
        self.assertIs(statements[1].right_op.base, statements[0].left_op)
        self.assertIs(statements[2].left_op.base, statements[0].left_op)
        self.assertEqual(result.classes[OWNER].fields["balance"], ((), "short"))

    def test_exception_edges_order_and_traps_are_not_declared_throws(self):
        x, ex = local("x"), local("ex", "java.lang.Throwable")
        units = [
            Unit(0, "assign", 10, 0, left=x, right=Expr("binary", "int", (constant(1), constant(0)), "div"), handlers=(0, 1)),
            Unit(1, "return", 11, 0, right=x),
            Unit(2, "identity", None, None, left=ex, right=Value("caught_exception", "java.lang.Throwable")),
            Unit(3, "return", 20, 1, right=constant(40)),
            Unit(4, "identity", None, None, left=ex, right=Value("caught_exception", "java.lang.Throwable")),
            Unit(5, "return", 30, 2, right=constant(50)),
        ]
        traps = (Trap(0, 1, 2, "java.lang.ArithmeticException", 0, False),
                 Trap(0, 1, 4, "java.lang.Throwable", 1, True))
        result = adapt(body(units, (x, ex), traps=traps))
        method = result.methods["method"]
        entry = method.blocks[0]
        self.assertEqual(tuple(b.label for b in method.basic_cfg[entry]), (2, 4))
        self.assertEqual(method.exceptional_preds[method.block_by_label[2]], (entry,))
        self.assertEqual(method.exceptions, ())
        self.assertEqual(result.details["method"].traps, traps)
        self.assertIn("ordered_exception_dispatch", result.required_backend_features)

    def test_external_calls_remain_explicit_obligations(self):
        ref = MethodRef("external", "javacard.framework.ISOException", "unbound", ("short",), "void", True, False)
        source = body([
            Unit(0, "invoke", 0, 0, right=Expr("invoke", "void", (constant(0x6A80, "short"),), method=ref, mode="static")),
            Unit(1, "return_void", 3, 0),
        ], returns="void")
        result = adapt(source)
        self.assertEqual(result.external_methods, (ref,))
        self.assertNotIn(ref.owner, result.classes)
        with self.assertRaisesRegex(AdapterError, "external"):
            result.require_resolved_symbols()

    def test_bad_parameter_and_unknown_schema_rejected(self):
        x = local("x")
        source = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=1)),
            Unit(1, "return", 0, 0, right=x),
        ], (x,), params=("int",))
        with self.assertRaisesRegex(AdapterError, "parameter"):
            adapt(source)
        with self.assertRaisesRegex(AdapterError, "schema"):
            adapt(replace(source, schema="unknown"))

    def test_missing_class_or_method_metadata_fails(self):
        source = body([Unit(0, "return", 0, 0, right=constant(1))])
        with self.assertRaisesRegex(AdapterError, "declarations"):
            adapt(source, metadata=ProgramMetadata(()))
        with self.assertRaisesRegex(AdapterError, "declaration"):
            adapt(source, metadata=ProgramMetadata((ClassMetadata(OWNER, "java.lang.Object"),)))

    def test_static_field_null_unary_and_array_nodes(self):
        arr, null, x, short = local("arr", "byte[]"), local("nil", "java.lang.Object"), local("x"), local("s", "short")
        byte = local("byte", "byte")
        field = FieldRef("static", OWNER, "counter", "short", True)
        units = [
            Unit(0, "assign", 0, 0, left=arr, right=Expr("new_array", "byte[]", (constant(2),))),
            Unit(1, "assign", 1, 0, left=Expr("array", "byte", (arr, constant(1))), right=constant(-1, "byte")),
            Unit(2, "assign", 2, 0, left=byte, right=Expr("array", "byte", (arr, constant(1)))),
            Unit(3, "assign", 3, 0, left=x, right=Expr("length", "int", (arr,))),
            Unit(4, "assign", 4, 0, left=x, right=Expr("unary", "int", (x,), "neg")),
            Unit(5, "assign", 5, 0, left=short, right=Expr("cast", "short", (x,))),
            Unit(6, "assign", 6, 0, left=Expr("field", "short", field=field), right=short),
            Unit(7, "assign", 7, 0, left=null, right=constant(None, "null")),
            Unit(8, "return_void", 8, 0),
        ]
        source = body(units, (arr, null, x, short, byte), returns="void")
        result = adapt(source, metadata=declarations(source, fields=(FieldMetadata("static", "counter", "short", ("STATIC",)),)))
        statements = result.methods["method"].blocks[0].statements
        self.assertEqual(statements[0].right_op.base_type, "byte")
        self.assertEqual(statements[1].left_op.index.value, 1)
        self.assertIs(statements[1].left_op.base, statements[2].right_op.base)
        self.assertEqual(statements[4].right_op.op, "neg")
        self.assertEqual(statements[6].left_op.field, ("counter", OWNER))
        self.assertEqual(type(statements[7].right_op).__name__, "SootNullConstant")

    def test_abstract_interface_and_interface_call(self):
        interface = "example.Service"
        receiver = local("service", interface)
        declaration = MethodMetadata("interface", "accept", (), "void", ("PUBLIC", "ABSTRACT"))
        ref = MethodRef("interface", interface, "accept", (), "void", False)
        caller = body([
            Unit(0, "identity", None, None, left=receiver, right=Value("parameter", interface, index=0)),
            Unit(1, "invoke", 0, 0, right=Expr("invoke", "void", (receiver,), method=ref, mode="interface")),
            Unit(2, "return_void", 3, 0),
        ], (receiver,), params=(interface,), returns="void")
        meta = declarations(caller)
        meta = replace(meta, classes=(*meta.classes, ClassMetadata(interface, "java.lang.Object",
                       attrs=("PUBLIC", "INTERFACE", "ABSTRACT"), methods=(declaration,))))
        result = adapt(caller, metadata=meta)
        self.assertEqual(result.methods["interface"].blocks, ())
        invoke = result.methods["method"].blocks[0].statements[1].invoke_expr
        self.assertEqual(type(invoke).__name__, "SootInterfaceInvokeExpr")
        self.assertEqual(invoke.class_name, interface)

    def test_throw_is_preserved_with_backend_requirement(self):
        ex = local("ex", "java.lang.Throwable")
        source = body([
            Unit(0, "identity", None, None, left=ex, right=Value("parameter", ex.type, index=0)),
            Unit(1, "throw", 4, 0, right=ex),
        ], (ex,), params=(ex.type,), returns="void")
        result = adapt(source)
        self.assertEqual(type(result.methods["method"].blocks[0].statements[1]).__name__, "ThrowStmt")
        self.assertIn("ordered_exception_dispatch", result.required_backend_features)

    def test_backend_import_does_not_start_jvm(self):
        import jpype
        self.assertFalse(jpype.isJVMStarted())
        self.assertTrue(load_backend().SootMethod.__module__.startswith("pysoot.sootir."))
        self.assertFalse(jpype.isJVMStarted())


class CAPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import main
        cls.cap = main.load_cap(main.PROJECT_DIR / "example.cap")
        cls.symbols = main.load_symbols(main.PROJECT_DIR / "soot_ir/soot_symbols.example.json")
        methods = main.extract_methods(cls.cap)
        cfgs = main.build_cfgs(methods)
        main.verify_methods(methods)
        jcvm = main.build_jcvm_ir(cls.cap, methods, cfgs)
        jvm = main.build_jvm_like_ir(jcvm)
        cls.program = main.build_soot_ir(jvm, cls.symbols)
        cls.metadata = metadata_from_cap(cls.cap, cls.symbols)
        cls.result = PySootAdapter().build(cls.program, cls.metadata)

    def test_all_nine_methods_preserve_instructions_edges_and_offsets(self):
        self.assertEqual(len(self.result.classes), 1)
        self.assertEqual(len(self.result.methods), 9)
        self.assertEqual(sum(len(m.units) for m in self.program.methods), 393)
        for source in self.program.methods:
            actual = self.result.methods[source.symbol.key]
            statements = [s for b in actual.blocks for s in b.statements]
            self.assertEqual([s.label for s in statements], [u.label for u in source.units])
            self.assertEqual([s.offset for s in statements], [u.offset if u.offset is not None else -1 for u in source.units])
            for b in source.blocks:
                self.assertEqual(tuple(s.idx for s in actual.basic_cfg.get(actual.blocks[b.index], ())), b.successors)
            self.assertEqual(self.result.details[source.symbol.key].source_map, source.source_map)

    def test_constructor_access_flags_and_field_declarations(self):
        cls = next(iter(self.result.classes.values()))
        self.assertEqual(cls.attrs, ("PUBLIC",))
        self.assertEqual(cls.super_class, "cap.pa0000000620101.v1_4.C3")
        init = next(m for m in cls.methods if m.name == "<init>")
        self.assertEqual(init.attrs, ("PROTECTED", "CONSTRUCTOR"))
        self.assertEqual(init.params, ("byte[]", "short", "byte"))
        self.assertEqual(cls.fields["field_t2_1"], ((), "short"))

    def test_metadata_requires_offsets_and_matching_imports(self):
        info = self.cap.class_component.classes[0]
        broken_cap = replace(self.cap, class_component=replace(self.cap.class_component, classes=[replace(info, offset=None)]))
        with self.assertRaisesRegex(AdapterError, "offsets are missing"):
            metadata_from_cap(broken_cap, self.symbols)
        with self.assertRaisesRegex(AdapterError, "imports"):
            metadata_from_cap(self.cap, replace(self.symbols, imports=tuple(reversed(self.symbols.imports))))

    def test_class_offsets_are_info_relative_and_join_is_not_positional(self):
        from cap_decompile.components.class_component import ClassComponent
        from cap_decompile.components.header import CAPVersion
        one = bytes([0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0])
        data = b"\x06" + (2 * len(one)).to_bytes(2, "big") + one + one
        component = ClassComponent.parse_from_bytes(data, CAPVersion.V22)
        self.assertEqual([c.offset for c in component.classes], [0, 10])
        first = self.cap.descriptor.classes[0]
        a = replace(first, fields=[], methods=[], field_count=0, method_count=0)
        other = replace(a, this_class_ref=10, token=1)
        cap = replace(self.cap, class_component=replace(component, classes=list(reversed(component.classes))),
                      descriptor=replace(self.cap.descriptor, classes=[a, other], class_count=2))
        metadata = metadata_from_cap(cap, self.symbols)
        self.assertEqual([c.offset for c in metadata.classes], [0, 10])
        self.assertNotEqual(metadata.classes[0].name, metadata.classes[1].name)

    def test_diagnostics_export_is_deterministic_and_has_source_mapping(self):
        original = self.program.to_json()
        repeated = PySootAdapter().build(self.program, self.metadata)
        self.assertEqual(self.result.to_json(), repeated.to_json())
        self.assertEqual(self.program.to_json(), original)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / "outputs/pysoot_output"
            self.result.export(directory)
            self.assertEqual(len(list(directory.iterdir())), 19)
            data = json.loads((directory / "program.json").read_text())
            self.assertEqual(data["schema"], "cap2soot.pysoot_adapter.program/1")
            self.assertEqual(len(data["methods"]), 9)
            self.assertTrue(data["methods"][0]["cap"]["source_map"])
            self.assertEqual(len(data["unresolved_symbols"]), 19)


if __name__ == "__main__":
    unittest.main()
