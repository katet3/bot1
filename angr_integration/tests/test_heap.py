"""Memory behavior checked through real angr states, branches and calls."""
from dataclasses import replace
import unittest
import tempfile

from angr_integration import AngrLoader, ExecutionNotReady, HeapError, LoaderError, SymbolicArgument
from pysoot_adapter import ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata, PySootAdapter
from soot_ir import Expr, FieldRef, Local, Method, MethodRef, Program, Unit, Value
from soot_ir.builder import make_blocks


OWNER = "heap.Cell"


def local(name, ty="int"):
    return Value("local", ty, name=name)


def const(n, ty="int"):
    return Value("constant", ty, value=n)


def unit(label, kind, **kwargs):
    return Unit(label, kind, label * 2, 0, **kwargs)


def field(base, name="value", ty="short", owner=OWNER):
    return Expr("field", ty, (base,), field=FieldRef(owner + "." + name, owner, name, ty, False))


def array(base, index):
    return Expr("array", base.type[:-2], (base, index))


def method(units, locals_=(), *, key="entry", params=(), ret="int", static=True, owner=OWNER):
    return Method(key, MethodRef(key, owner, key, params, ret, static),
                  tuple(Local(v.name, v.type) for v in locals_), tuple(units), make_blocks(units, ()), (),
                  tuple((u.offset, (u.label,)) for u in units))


def load(*methods, fields=(), extra_classes=(), super_class="java.lang.Object", **kwargs):
    declarations = tuple(MethodMetadata(m.symbol.key, m.symbol.name, m.symbol.params, m.symbol.returns,
                                       ("PUBLIC", "STATIC") if m.symbol.is_static else ("PUBLIC",)) for m in methods)
    metadata = ProgramMetadata((ClassMetadata(OWNER, super_class, fields=fields, methods=declarations), *extra_classes))
    adapted = PySootAdapter().build(Program(tuple(methods), ()), metadata)
    return AngrLoader().load(adapted, entry_key=methods[0].symbol.key, **kwargs)


def value_field(ty="short", name="value", owner=OWNER):
    return FieldMetadata(owner + "." + name, name, ty)


def array_method(*, write=False, ty="byte"):
    a, i, out = local("a", ty + "[]"), local("i"), local("out", ty)
    units = [unit(0, "identity", left=a, right=Value("parameter", a.type, index=0)),
             unit(1, "identity", left=i, right=Value("parameter", "int", index=1))]
    if write:
        units.append(unit(2, "assign", left=array(a, i), right=const(9, ty)))
    units.extend([unit(len(units), "assign", left=out, right=array(a, i)),
                  unit(len(units) + 1, "return", right=out)])
    return method(units, (a, i, out), params=(a.type, "int"), ret=ty)


class HeapTests(unittest.TestCase):
    def run_ok(self, loaded, state, count=1):
        manager = loaded.project.factory.simgr(state).run(n=40)
        if manager.errored:
            manager.errored[0].reraise()
        self.assertFalse(manager.active)
        self.assertEqual(len(manager.deadended), count)
        return manager.deadended

    def run_fault(self, loaded, state, code):
        manager = loaded.project.factory.simgr(state).run(n=40)
        self.assertFalse(manager.active)
        self.assertFalse(manager.deadended)
        self.assertEqual(len(manager.errored), 1)
        error = manager.errored[0].error
        self.assertEqual(error.code, code)
        self.assertIsNotNone(error.source.cap_offset)
        return manager.errored[0]

    def test_symbolic_paths_modify_fields_and_arrays_independently(self):
        from angr_integration.memory_demo import run_demo
        with tempfile.TemporaryDirectory() as directory:
            report = run_demo(directory)
        self.assertEqual(report["deadended"], 2)
        self.assertEqual(report["errored"], 0)
        self.assertTrue(report["base_state_unchanged"])
        self.assertEqual([p["field_value"] for p in report["paths"]], [-7, 7])
        self.assertEqual([p["array_signed"] for p in report["paths"]], [[-7, 0], [7, 0]])

    def test_new_object_default_fields_alias_and_narrow_storage(self):
        a, alias, out, before = local("a", OWNER), local("alias", OWNER), local("out", "short"), local("before", "short")
        m = method([
            unit(0, "assign", left=a, right=Expr("new", OWNER)),
            unit(1, "assign", left=before, right=field(a)),
            unit(2, "assign", left=alias, right=a),
            unit(3, "assign", left=field(alias), right=const(65535, "short")),
            unit(4, "assign", left=out, right=field(a)),
            unit(5, "return", right=out),
        ], (a, alias, out, before), ret="short")
        loaded = load(m, fields=(value_field(),))
        end = self.run_ok(loaded, loaded.create_call_state())[0]
        self.assertEqual(end.solver.eval(end.regs.invoke_return_value), 0xffffffff)
        self.assertEqual(len(end.cap_heap._references), 1)

    def test_receiver_and_inherited_fields_are_typed_and_base_is_unchanged(self):
        parent = "heap.Parent"
        this, out = local("self", OWNER), local("out", "short")
        m = method([unit(0, "identity", left=this, right=Value("this", OWNER)),
                    unit(1, "assign", left=field(this, owner=parent), right=const(12, "short")),
                    unit(2, "assign", left=out, right=field(this, owner=parent)),
                    unit(3, "return", right=out)], (this, out), static=False, ret="short")
        loaded = load(m, fields=(value_field(),), super_class=parent,
                      extra_classes=(ClassMetadata(parent, "java.lang.Object", fields=(value_field(owner=parent),)),))
        base = loaded.create_heap_state()
        ref = base.cap_heap.new_object(OWNER)
        base.cap_heap.write_field(ref, OWNER, "value", "short", 99)
        end = self.run_ok(loaded, loaded.create_call_state(receiver=ref, base_state=base))[0]
        self.assertEqual(end.solver.eval(end.cap_heap.read_field(ref, parent, "value", "short")), 12)
        self.assertEqual(base.solver.eval(base.cap_heap.read_field(ref, parent, "value", "short")), 0)
        self.assertEqual(end.solver.eval(end.cap_heap.read_field(ref, OWNER, "value", "short")), 99)

    def test_all_primitive_arrays_defaults_length_and_storage_width(self):
        for ty, value, expected in [("byte", 255, 0xffffffff), ("short", 65535, 0xffffffff),
                                    ("int", -123, 0xffffff85), ("boolean", 1, 1)]:
            with self.subTest(type=ty):
                a, out, length = local("a", ty + "[]"), local("out", ty), local("length")
                m = method([unit(0, "assign", left=a, right=Expr("new_array", a.type, (const(2),))),
                            unit(1, "assign", left=array(a, const(0)), right=const(value, ty)),
                            unit(2, "assign", left=length, right=Expr("length", "int", (a,))),
                            unit(3, "assign", left=out, right=array(a, const(0))),
                            unit(4, "return", right=out)], (a, out, length), ret=ty)
                loaded = load(m)
                end = self.run_ok(loaded, loaded.create_call_state())[0]
                self.assertEqual(end.solver.eval(end.regs.invoke_return_value), expected)
                ref = next(iter(end.cap_heap._references.values()))
                self.assertEqual(end.solver.eval(end.cap_heap.array_length(ref)), 2)
                self.assertEqual(end.solver.eval(end.cap_heap.read_array(ref, 1)), 0)

    def test_symbolic_primitive_array_read_preserves_all_valid_indices(self):
        loaded = load(array_method())
        base = loaded.create_heap_state()
        a = base.cap_heap.new_array("byte", 2)
        base.cap_heap.write_array(a, 0, 10)
        base.cap_heap.write_array(a, 1, 20)
        state = loaded.create_call_state(args=[a, SymbolicArgument("index")], base_state=base)
        index = state.globals["cap2soot.inputs"][1]
        state.add_constraints(index.SGE(0), index.SLT(2))
        end = self.run_ok(loaded, state)[0]
        self.assertEqual(set(end.solver.eval_upto(end.regs.invoke_return_value, 3)), {10, 20})
        self.assertTrue(end.solver.satisfiable(extra_constraints=[index == 0, end.regs.invoke_return_value == 10]))
        self.assertTrue(end.solver.satisfiable(extra_constraints=[index == 1, end.regs.invoke_return_value == 20]))

    def test_symbolic_write_is_conditional_and_does_not_modify_base_state(self):
        loaded = load(array_method(write=True))
        base = loaded.create_heap_state()
        a = base.cap_heap.new_array("byte", 2)
        state = loaded.create_call_state(args=[a, SymbolicArgument("write_index")], base_state=base)
        index = state.globals["cap2soot.inputs"][1]
        state.add_constraints(index.SGE(0), index.SLT(2))
        end = self.run_ok(loaded, state)[0]
        zero, one = end.cap_heap.read_array(a, 0), end.cap_heap.read_array(a, 1)
        self.assertTrue(end.solver.satisfiable(extra_constraints=[index == 0, zero == 9, one == 0]))
        self.assertTrue(end.solver.satisfiable(extra_constraints=[index == 1, zero == 0, one == 9]))
        self.assertFalse(end.solver.satisfiable(extra_constraints=[zero == 9, one == 9]))
        self.assertEqual(base.solver.eval(base.cap_heap.read_array(a, 0)), 0)

    def test_out_of_bounds_and_possible_fault_are_not_pruned(self):
        loaded = load(array_method())
        base = loaded.create_heap_state()
        a = base.cap_heap.new_array("byte", 2)
        for index in [-1, 2, SymbolicArgument("possibly_bad")]:
            with self.subTest(index=index):
                state = loaded.create_call_state(args=[a, index], base_state=base)
                fault = self.run_fault(loaded, state, "array_bounds")
                self.assertEqual(fault.error.source.unit_label, 2)
                if isinstance(index, SymbolicArgument):
                    raw = state.globals["cap2soot.inputs"][1]
                    self.assertTrue(fault.state.solver.satisfiable(extra_constraints=[raw == -1]))
                    self.assertTrue(fault.state.solver.satisfiable(extra_constraints=[raw == 0]))
                    self.assertTrue(fault.state.solver.satisfiable(extra_constraints=[fault.error.condition]))

    def test_null_field_array_and_length_faults_have_source_locations(self):
        a, o, x = local("a", "byte[]"), local("o", OWNER), local("x")
        for ref, expr in [(a, array(a, const(0))), (a, Expr("length", "int", (a,))), (o, field(o))]:
            x = local("x", expr.type)
            m = method([unit(0, "identity", left=ref, right=Value("parameter", ref.type, index=0)),
                        unit(1, "assign", left=x, right=expr), unit(2, "return", right=x)],
                       (ref, x), params=(ref.type,), ret=expr.type)
            loaded = load(m, fields=(value_field(),))
            fault = self.run_fault(loaded, loaded.create_call_state(args=[None]), "null_reference")
            self.assertEqual(fault.error.source.cap_offset, 2)

    def test_allocation_length_is_never_clamped_or_arbitrarily_concretized(self):
        n, a = local("n"), local("a", "byte[]")
        m = method([unit(0, "identity", left=n, right=Value("parameter", "int", index=0)),
                    unit(1, "assign", left=a, right=Expr("new_array", a.type, (n,))),
                    unit(2, "return", right=a)], (n, a), params=("int",), ret=a.type)
        loaded = load(m, max_array_length=2)
        self.run_fault(loaded, loaded.create_call_state(args=[-1]), "negative_array_size")
        self.run_fault(loaded, loaded.create_call_state(args=[3]), "array_resource_limit")
        state = loaded.create_call_state(args=[SymbolicArgument("length")])
        size = state.globals["cap2soot.inputs"][0]
        state.add_constraints(size.SGE(0), size.SLE(2))
        self.run_fault(loaded, state, "symbolic_array_size")
        state.add_constraints(size == 2)
        end = self.run_ok(loaded, state)[0]
        self.assertEqual(end.solver.eval(end.cap_heap.array_length(end.regs.invoke_return_value)), 2)
        empty = self.run_ok(loaded, loaded.create_call_state(args=[0]))[0]
        self.assertEqual(empty.solver.eval(empty.cap_heap.array_length(empty.regs.invoke_return_value)), 0)

    def test_references_are_returned_and_alias_through_static_calls(self):
        a, result, p = local("a", "byte[]"), local("result", "byte[]"), local("p", "byte[]")
        callee = method([unit(0, "identity", left=p, right=Value("parameter", p.type, index=0)),
                         unit(1, "assign", left=array(p, const(0)), right=const(-8, "byte")),
                         unit(2, "return", right=p)], (p,), key="callee", params=(p.type,), ret=p.type)
        caller = method([unit(0, "identity", left=a, right=Value("parameter", a.type, index=0)),
                         unit(1, "assign", left=result, right=Expr("invoke", a.type, (a,), method=callee.symbol, mode="static")),
                         unit(2, "return", right=result)], (a, result), params=(a.type,), ret=a.type)
        loaded = load(caller, callee)
        base = loaded.create_heap_state()
        ref = base.cap_heap.new_array("byte", 1)
        end = self.run_ok(loaded, loaded.create_call_state(args=[ref], base_state=base))[0]
        self.assertEqual(end.regs.invoke_return_value, ref)
        self.assertEqual(end.solver.eval(end.cap_heap.read_array(ref, 0)), 0xfffffff8)
        self.assertEqual(base.solver.eval(base.cap_heap.read_array(ref, 0)), 0)

    def test_reference_equality_distinguishes_alias_fresh_object_and_null(self):
        a, b = local("a", OWNER), local("b", OWNER)
        m = method([unit(0, "identity", left=a, right=Value("parameter", OWNER, index=0)),
                    unit(1, "identity", left=b, right=Value("parameter", OWNER, index=1)),
                    unit(2, "if", right=Expr("condition", "boolean", (a, b), "eq"), target=4),
                    unit(3, "return", right=const(0)), unit(4, "return", right=const(1))],
                   (a, b), params=(OWNER, OWNER))
        loaded = load(m)
        base = loaded.create_heap_state()
        x, y = base.cap_heap.new_object(OWNER), base.cap_heap.new_object(OWNER)
        for args, result in [([x, x], 1), ([x, y], 0), ([None, None], 1), ([x, None], 0)]:
            end = self.run_ok(loaded, loaded.create_call_state(args=args, base_state=base))[0]
            self.assertEqual(end.solver.eval(end.regs.invoke_return_value), result)

    def test_reference_cast_preserves_dynamic_type_and_checks_mismatch(self):
        child, other = "heap.Child", "heap.Other"
        p, c = local("p", OWNER), local("c", child)
        m = method([unit(0, "identity", left=p, right=Value("parameter", OWNER, index=0)),
                    unit(1, "assign", left=c, right=Expr("cast", child, (p,))),
                    unit(2, "return", right=c)], (p, c), params=(OWNER,), ret=child)
        loaded = load(m, extra_classes=(ClassMetadata(child, OWNER), ClassMetadata(other, OWNER)))
        base = loaded.create_heap_state()
        child_ref = base.cap_heap.new_object(child)
        end = self.run_ok(loaded, loaded.create_call_state(args=[child_ref], base_state=base))[0]
        self.assertEqual(end.regs.invoke_return_value, child_ref)
        bad = base.cap_heap.new_object(other)
        self.run_fault(loaded, loaded.create_call_state(args=[bad], base_state=base), "class_cast")
        null_end = self.run_ok(loaded, loaded.create_call_state(args=[None]))[0]
        self.assertIsInstance(null_end.regs.invoke_return_value, loaded.dependencies.arch.SootNullConstant)

    def test_foreign_or_forged_references_are_rejected(self):
        loaded = load(array_method())
        first, second = loaded.create_heap_state(), loaded.create_heap_state()
        a = first.cap_heap.new_array("byte", 1)
        with self.assertRaisesRegex(HeapError, "foreign_reference"):
            loaded.create_call_state(args=[a, 0], base_state=second)
        with self.assertRaisesRegex(HeapError, "foreign_reference"):
            loaded.create_call_state(args=[replace(a, type="short[]"), 0], base_state=first)
        with self.assertRaisesRegex(LoaderError, "base_state"):
            loaded.create_call_state(args=[a, 0])
        self.run_ok(loaded, loaded.create_call_state(args=[a, 0], base_state=first.copy()))

    def test_reference_array_defaults_covariance_and_bad_store(self):
        child, other = "heap.Child", "heap.Other"
        a, p, out = local("a", OWNER + "[]"), local("p", OWNER), local("out", OWNER)
        m = method([unit(0, "identity", left=a, right=Value("parameter", a.type, index=0)),
                    unit(1, "identity", left=p, right=Value("parameter", OWNER, index=1)),
                    unit(2, "assign", left=array(a, const(0)), right=p),
                    unit(3, "assign", left=out, right=array(a, const(0))),
                    unit(4, "return", right=out)], (a, p, out), params=(a.type, OWNER), ret=OWNER)
        loaded = load(m, extra_classes=(ClassMetadata(child, OWNER), ClassMetadata(other, OWNER)))
        base = loaded.create_heap_state()
        arr = base.cap_heap.new_array(child, 1)
        self.assertIsInstance(base.cap_heap.read_array(arr, 0), loaded.dependencies.arch.SootNullConstant)
        ref = base.cap_heap.new_object(child)
        end = self.run_ok(loaded, loaded.create_call_state(args=[arr, ref], base_state=base))[0]
        self.assertEqual(end.regs.invoke_return_value, ref)
        bad = base.cap_heap.new_object(other)
        self.run_fault(loaded, loaded.create_call_state(args=[arr, bad], base_state=base), "array_store")

    def test_symbolic_reference_array_index_and_state_merge_fail_explicitly(self):
        from angr.errors import SimMergeError
        loaded = load(array_method(ty=OWNER))
        base = loaded.create_heap_state()
        arr = base.cap_heap.new_array(OWNER, 2)
        state = loaded.create_call_state(args=[arr, SymbolicArgument("ref_index")], base_state=base)
        i = state.globals["cap2soot.inputs"][1]
        state.add_constraints(i.SGE(0), i.SLT(2))
        self.run_fault(loaded, state, "symbolic_reference_index")
        with self.assertRaisesRegex(SimMergeError, "merging"):
            base.merge(base.copy())

    def test_external_hierarchy_and_static_fields_are_not_fabricated(self):
        obj = local("o", OWNER)
        m = method([unit(0, "assign", left=obj, right=Expr("new", OWNER)), unit(1, "return", right=obj)], (obj,), ret=OWNER)
        loaded = load(m, super_class="external.Unknown")
        with self.assertRaisesRegex(ExecutionNotReady, "Missing class declaration"):
            loaded.create_call_state()
        base = loaded.create_heap_state()
        with self.assertRaisesRegex(HeapError, "class_hierarchy"):
            base.cap_heap.new_object(OWNER)
        self.assertFalse(base.cap_heap._references)
        ref = FieldRef("static", OWNER, "s", "short", True)
        m = method([unit(0, "return", right=Expr("field", "short", field=ref))], ret="short")
        loaded = load(m, fields=(FieldMetadata("static", "s", "short", ("STATIC",)),))
        with self.assertRaisesRegex(ExecutionNotReady, "SootStaticFieldRef"):
            loaded.create_call_state()


if __name__ == "__main__":
    unittest.main()
