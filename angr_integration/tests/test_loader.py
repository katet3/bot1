"""Real CLE/angr/solver integration tests, without Java, JARs or a mock executor."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from soot_ir import Expr, Local, Method, MethodRef, Program, Trap, Unit, Value
from soot_ir.builder import make_blocks
from pysoot_adapter import ClassMetadata, MethodMetadata, ProgramMetadata, PySootAdapter
from angr_integration import AngrLoader, ExecutionNotReady, LoaderError, SymbolicArgument


OWNER = "loader.Test"


def local(name, ty="int"):
    return Value("local", ty, name=name)


def const(value):
    return Value("constant", "int", value=value)


def body(units, locals_=(), *, key="entry", params=(), ret="int", static=True, traps=()):
    return Method(key, MethodRef(key, OWNER, key, params, ret, static),
                  tuple(Local(v.name, v.type) for v in locals_), tuple(units),
                  make_blocks(units, traps), tuple(traps),
                  tuple((u.offset, (u.label,)) for u in units if u.offset is not None))


def adapt(*methods):
    metadata = ProgramMetadata((ClassMetadata(OWNER, "java.lang.Object", attrs=("PUBLIC",), methods=tuple(
        MethodMetadata(m.symbol.key, m.symbol.name, m.symbol.params, m.symbol.returns,
                       ("PUBLIC", "STATIC") if m.symbol.is_static else ("PUBLIC",)) for m in methods
    )),))
    return PySootAdapter().build(Program(tuple(methods), ()), metadata)


def branch_method():
    x = local("x")
    return body([
        Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
        Unit(1, "if", 0, 0, right=Expr("condition", "boolean", (x, const(0)), "lt"), target=4),
        Unit(2, "assign", 2, 1, left=x, right=const(7)),
        Unit(3, "goto", 3, 1, target=5),
        Unit(4, "assign", 4, 2, left=x, right=const(-7)),
        Unit(5, "return", 5, 3, right=x),
    ], (x,), params=("int",))


def signed32(n):
    return n - (1 << 32) if n & (1 << 31) else n


class LoaderTests(unittest.TestCase):
    def execute(self, loaded, state, steps=30):
        manager = loaded.project.factory.simgr(state).run(n=steps)
        if manager.errored:
            manager.errored[0].reraise()
        self.assertFalse(manager.active, "Test execution exceeded its step budget")
        return manager.deadended

    def returns(self, states):
        return sorted(signed32(s.solver.eval(s.regs.invoke_return_value)) for s in states)

    def test_real_loader_no_lifter_jvm_or_implicit_library_bodies(self):
        import jpype
        from cle.backends.java.soot import Soot
        with patch("pysoot.lifter.Lifter", side_effect=AssertionError("No Java lifting")), \
                patch("jpype.startJVM", side_effect=AssertionError("No JVM")):
            adapted = adapt(branch_method())
            loaded = AngrLoader().load(adapted)
        self.assertIsInstance(loaded.project.loader.main_object, Soot)
        self.assertEqual(loaded.project.arch.name, "Soot")
        self.assertIs(loaded.project.loader.main_object.classes[OWNER], adapted.classes[OWNER])
        self.assertIs(loaded.project.loader.main_object.get_soot_method(loaded.project.entry.method), adapted.methods["entry"])
        self.assertIsNone(loaded.project.loader.main_object.get_soot_class("java.lang.Object", none_if_missing=True))
        self.assertFalse(jpype.isJVMStarted())

    def test_source_address_roundtrip_distinguishes_labels_blocks_and_offsets(self):
        loaded = AngrLoader().load(adapt(branch_method()))
        address = loaded.address_for_label("entry", 4)
        self.assertEqual((address.block_idx, address.stmt_idx), (2, 0))
        self.assertEqual(loaded.source_location(address).cap_offset, 4)
        self.assertIsNone(loaded.source_location(loaded.method_address("entry")).cap_offset)
        self.assertEqual(loaded.addresses_for_offset("entry", 4), (address,))
        self.assertEqual(loaded.addresses_for_offset("entry", 999), ())
        for loc in loaded.index.locations.values():
            self.assertEqual(loaded.source_location(loaded.index.address(loc)), loc)
        with self.assertRaises(LoaderError):
            loaded.address_for_label("entry", 100)
        with self.assertRaises(LoaderError):
            loaded.source_location(loaded.dependencies.arch.SootAddressTerminator())

    def test_symbolic_signed_branch_forks_and_solves_real_constraints(self):
        loaded = AngrLoader().load(adapt(branch_method()))
        state = loaded.create_call_state(args=[SymbolicArgument("branch_x")])
        symbol = state.globals["cap2soot.inputs"][0]
        states = self.execute(loaded, state)
        self.assertEqual(self.returns(states), [-7, 7])
        for end in states:
            result = signed32(end.solver.eval(end.regs.invoke_return_value))
            wrong = loaded.dependencies.claripy.SGE(symbol, 0) if result == -7 else loaded.dependencies.claripy.SLT(symbol, 0)
            self.assertFalse(end.solver.satisfiable(extra_constraints=[wrong]))
        nonnegative = state.copy()
        nonnegative.solver.add(loaded.dependencies.claripy.SGE(symbol, 0))
        self.assertEqual(self.returns(self.execute(loaded, nonnegative)), [7])

    def test_primitive_widths_and_sign_extension(self):
        for ty, values in [("byte", (-128, -1, 0, 127)), ("short", (-32768, 32767)),
                           ("int", (-2147483648, 2147483647)), ("boolean", (0, 1))]:
            x = local("x", ty)
            method = body([
                Unit(0, "identity", None, None, left=x, right=Value("parameter", ty, index=0)),
                Unit(1, "return", 0, 0, right=x),
            ], (x,), params=(ty,), ret=ty)
            loaded = AngrLoader().load(adapt(method))
            for value in values:
                with self.subTest(type=ty, value=value):
                    self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state(args=[value]))), [value])
            symbolic = loaded.create_call_state(args=[SymbolicArgument("typed_" + ty)])
            result = self.execute(loaded, symbolic)[0]
            widths = {"byte": 8, "short": 16, "boolean": 1, "int": 32}
            self.assertEqual(result.globals["cap2soot.inputs"][0].size(), widths[ty])
            expected = result.globals["cap2soot.inputs"][0]
            if ty == "boolean":
                expected = expected.zero_extend(31)
            elif ty != "int":
                expected = expected.sign_extend(32 - widths[ty])
            self.assertFalse(result.solver.satisfiable(extra_constraints=[result.regs.invoke_return_value != expected]))

    def test_short_wraparound_casts_are_executed_by_angr(self):
        x, y, narrow = local("x"), local("y"), local("n", "short")
        method = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "assign", 0, 0, left=y, right=Expr("binary", "int", (x, const(1)), "add")),
            Unit(2, "assign", 1, 0, left=narrow, right=Expr("cast", "short", (y,))),
            Unit(3, "assign", 2, 0, left=y, right=Expr("cast", "int", (narrow,))),
            Unit(4, "return", 3, 0, right=y),
        ], (x, y, narrow), params=("int",))
        loaded = AngrLoader().load(adapt(method))
        self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state(args=[32767]))), [-32768])
        self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state(args=[-1]))), [0])

    def test_internal_static_call_transfers_args_and_returns_to_caller(self):
        x, y = local("x"), local("y")
        callee = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "assign", 0, 0, left=x, right=Expr("binary", "int", (x, const(2)), "mul")),
            Unit(2, "return", 1, 0, right=x),
        ], (x,), key="double", params=("int",))
        caller = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "assign", 0, 0, left=y, right=Expr("invoke", "int", (x,), method=callee.symbol, mode="static")),
            Unit(2, "assign", 3, 0, left=y, right=Expr("binary", "int", (y, const(1)), "add")),
            Unit(3, "return", 4, 0, right=y),
        ], (x, y), params=("int",))
        loaded = AngrLoader().load(adapt(caller, callee), entry_key="entry")
        self.assertEqual(loaded.readiness.reachable("entry"), ("double", "entry"))
        self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state(args=[-3]))), [-5])

    def test_switch_shared_targets_negative_case_and_default(self):
        x = local("x")
        method = body([
            Unit(0, "identity", None, None, left=x, right=Value("parameter", "int", index=0)),
            Unit(1, "switch", 0, 0, right=x, cases=((-1, 2), (7, 2)), default_target=3),
            Unit(2, "return", 4, 1, right=const(10)),
            Unit(3, "return", 5, 2, right=const(20)),
        ], (x,), params=("int",))
        loaded = AngrLoader().load(adapt(method))
        for value, expected in [(-1, 10), (7, 10), (0, 20)]:
            self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state(args=[value]))), [expected])
        symbolic = loaded.create_call_state(args=[SymbolicArgument("switch_x")])
        endings = self.execute(loaded, symbolic)
        self.assertEqual(set(self.returns(endings)), {10, 20})

    def test_loop_step_budget_keeps_active_state(self):
        method = body([Unit(0, "goto", 0, 0, target=0)], ret="void")
        loaded = AngrLoader().load(adapt(method))
        manager = loaded.project.factory.simgr(loaded.create_call_state()).run(n=3)
        self.assertEqual(len(manager.active), 1)
        self.assertFalse(manager.deadended)
        self.assertFalse(manager.errored)

    def test_external_call_loaded_but_never_given_an_unconstrained_return(self):
        ref = MethodRef("api", "javacard.framework.ISOException", "throwIt", ("int",), "void", True, False)
        method = body([
            Unit(0, "invoke", 0, 0, right=Expr("invoke", "void", (const(0x6300),), method=ref, mode="static")),
            Unit(1, "return_void", 3, 0),
        ], ret="void")
        loaded = AngrLoader().load(adapt(method))
        self.assertTrue(loaded.to_dict()["loaded"])
        with self.assertRaisesRegex(ExecutionNotReady, "Missing method/API model"):
            loaded.create_call_state()
        # The runtime guard also covers users of the raw angr factory.
        state = loaded.project.factory.call_state(loaded.method_address("entry"))
        manager = loaded.project.factory.simgr(state).run(n=3)
        self.assertEqual(len(manager.errored), 1)
        self.assertFalse(manager.deadended)

    def test_unknown_direct_address_cannot_use_stock_unconstrained_fallback(self):
        loaded = AngrLoader().load(adapt(body([Unit(0, "return", 0, 0, right=const(1))])))
        state = loaded.create_call_state()
        descriptor = loaded.dependencies.arch.SootMethodDescriptor("missing.API", "unknown", (), ret_type="int")
        state.regs._ip = descriptor.addr
        manager = loaded.project.factory.simgr(state).run(n=2)
        self.assertEqual(len(manager.errored), 1)
        self.assertIn("not loaded", str(manager.errored[0].error))

    def test_unsupported_callee_is_rejected_transitively(self):
        x = local("x")
        bad = body([
            Unit(0, "assign", 0, 0, left=x, right=Expr("binary", "int", (const(-7), const(3)), "div")),
            Unit(1, "return", 1, 0, right=x),
        ], (x,), key="divide")
        caller = body([
            Unit(0, "assign", 0, 0, left=x, right=Expr("invoke", "int", (), method=bad.symbol, mode="static")),
            Unit(1, "return", 3, 0, right=x),
        ], (x,))
        loaded = AngrLoader().load(adapt(caller, bad), entry_key="entry")
        with self.assertRaisesRegex(ExecutionNotReady, "divide"):
            loaded.create_call_state()

    def test_unsupported_operand_shapes_do_not_claim_execution_readiness(self):
        x, boolean = local("x"), local("b", "boolean")
        cast = body([
            Unit(0, "assign", 0, 0, left=x, right=const(3)),
            Unit(1, "assign", 1, 0, left=boolean, right=Expr("cast", "boolean", (x,))),
            Unit(2, "return", 2, 0, right=boolean),
        ], (x, boolean), ret="boolean")
        constant_switch = body([
            Unit(0, "switch", 0, 0, right=const(1), cases=((1, 1),), default_target=2),
            Unit(1, "return", 3, 1, right=const(7)),
            Unit(2, "return", 4, 2, right=const(9)),
        ])
        for method, code in [(cast, "boolean_cast"), (constant_switch, "switch_operand")]:
            loaded = AngrLoader().load(adapt(method))
            self.assertIn(code, {issue.code for issue in loaded.readiness.issues("entry")})
            with self.assertRaises(ExecutionNotReady):
                loaded.create_call_state()

    def test_exception_metadata_survives_loading_and_blocks_execution(self):
        ex = local("exception", "java.lang.Throwable")
        units = [Unit(0, "return", 0, 0, right=const(1)),
                 Unit(1, "identity", None, None, left=ex, right=Value("caught_exception", ex.type)),
                 Unit(2, "return", 5, 1, right=const(2))]
        trap = Trap(0, 1, 1, "java.lang.Throwable", 0, True)
        loaded = AngrLoader().load(adapt(body(units, (ex,), traps=(trap,))))
        self.assertEqual(loaded.program.details["entry"].traps, (trap,))
        with self.assertRaisesRegex(ExecutionNotReady, "exception"):
            loaded.create_call_state()

    def test_bad_arguments_and_entry_keys_are_explicit_errors(self):
        loaded = AngrLoader().load(adapt(branch_method()))
        for args in [[], [0, 1], [1 << 31], [object()]]:
            with self.subTest(args=args), self.assertRaises(LoaderError):
                loaded.create_call_state(args=args)
        with self.assertRaisesRegex(LoaderError, "32-bit"):
            loaded.create_call_state(args=[loaded.dependencies.claripy.BVS("wrong_width", 16)])
        with self.assertRaisesRegex(LoaderError, "Unknown CAP"):
            AngrLoader().load(adapt(branch_method()), entry_key="no-method")
        with self.assertRaisesRegex(LoaderError, "AdaptedProgram"):
            AngrLoader().load({"methods": []})

    def test_multiple_methods_do_not_choose_an_arbitrary_entry(self):
        first = body([Unit(0, "return", 0, 0, right=const(1))], key="one")
        second = body([Unit(0, "return", 0, 0, right=const(2))], key="two")
        loaded = AngrLoader().load(adapt(first, second))
        self.assertIsNone(loaded.project.entry)
        with self.assertRaisesRegex(LoaderError, "No unique entry"):
            loaded.create_call_state()
        self.assertEqual(self.returns(self.execute(loaded, loaded.create_call_state("two"))), [2])

    def test_receiver_is_explicit_and_base_state_is_copied(self):
        method = body([Unit(0, "return", 0, 0, right=const(4))], static=False)
        loaded = AngrLoader().load(adapt(method))
        with self.assertRaisesRegex(LoaderError, "receiver"):
            loaded.create_call_state()
        base = loaded.create_heap_state()
        receiver = base.cap_heap.new_object(OWNER)
        state = loaded.create_call_state(receiver=receiver, base_state=base)
        self.assertIsNot(state, base)
        self.assertEqual(self.returns(self.execute(loaded, state)), [4])
        self.assertEqual(base.addr, loaded.method_address("entry"))

    def test_interpreter_errors_are_recorded_not_skipped(self):
        loaded = AngrLoader().load(adapt(body([Unit(0, "return", 0, 0, right=const(4))])))
        from angr.errors import SimEngineError
        with patch("angr_integration.runtime.translate_stmt", side_effect=SimEngineError("sentinel failure")):
            manager = loaded.project.factory.simgr(loaded.create_call_state()).run(n=2)
        self.assertEqual(len(manager.errored), 1)
        self.assertIn("sentinel failure", str(manager.errored[0].error))
        self.assertFalse(manager.deadended)

    def test_actual_cap_pipeline_loads_all_methods_and_exports_source_map(self):
        from main import (PROJECT_DIR, build_cfgs, build_jcvm_ir, build_jvm_like_ir,
                          build_pysoot_model, build_soot_ir, extract_methods, load_cap, load_symbols)
        cap = load_cap(PROJECT_DIR / "example.cap")
        methods = extract_methods(cap)
        jvm = build_jvm_like_ir(build_jcvm_ir(cap, methods, build_cfgs(methods)))
        symbols = load_symbols(PROJECT_DIR / "soot_ir" / "soot_symbols.example.json")
        program = build_pysoot_model(cap, build_soot_ir(jvm, symbols), symbols)
        loaded = AngrLoader().load(program)
        self.assertEqual(len(loaded.project.loader.main_object.classes), 1)
        self.assertEqual(len(program.methods), 9)
        self.assertEqual(len(loaded.index.locations), 393)
        self.assertEqual(loaded.entry_key, program.metadata.applets[0].install_method_key)
        self.assertEqual(len(program.unresolved_symbols), 19)
        self.assertFalse(any(m["execution_ready"] for m in loaded.to_dict()["methods"]))
        for key, details in program.details.items():
            for label, offset, *_ in details.unit_origins:
                self.assertEqual(loaded.source_location(loaded.address_for_label(key, label)).cap_offset, offset)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "outputs" / "angr_output"
            loaded.export(directory)
            self.assertEqual({p.name for p in directory.iterdir()}, {"load_report.json", "load_report.txt", "addresses.json"})
            report = json.loads((directory / "load_report.json").read_text())
            self.assertTrue(report["loaded"])
            self.assertEqual(len(report["methods"]), 9)
            self.assertEqual(len(json.loads((directory / "addresses.json").read_text())), 393)
            before = (directory / "load_report.json").read_bytes()
            loaded.export(directory)
            self.assertEqual(before, (directory / "load_report.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
