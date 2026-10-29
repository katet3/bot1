"""Constructor/virtual/special calls and signed remainder through real angr."""
import unittest

from angr import claripy
from angr_integration import AngrLoader, SymbolicArgument
from pysoot_adapter import ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata, PySootAdapter
from soot_ir import Expr, FieldRef, Local, Method, MethodRef, Program, Unit, Value
from soot_ir.builder import make_blocks
from angr_integration.tests.test_heap import local, const, unit, method, load


def make_method(key, owner, name, params, ret, static, units, locals_):
    return Method(name, MethodRef(key, owner, name, params, ret, static),
                  tuple(Local(v.name, v.type) for v in locals_), tuple(units), make_blocks(units, ()), (),
                  tuple((u.offset, (u.label,)) for u in units))


def call_program(mode='virtual', null=False):
    base, child, caller = 'calls.Base', 'calls.Child', 'calls.Caller'
    b, c, obj, out = local('b', base), local('c', child), local('obj', child), local('out')
    declared = local('declared', base)
    field = FieldRef('field:value', base, 'value', 'int', False)
    ctor = make_method('ctor', child, '<init>', (), 'void', False, [
        unit(0, 'identity', left=c, right=Value('this', child)),
        unit(1, 'assign', left=Expr('field', 'int', (c,), field=field), right=const(17)),
        unit(2, 'return_void'),
    ], [c])
    original = make_method('base', base, 'baseBody', (), 'int', False, [
        unit(0, 'identity', left=b, right=Value('this', base)),
        unit(1, 'assign', left=out, right=Expr('field', 'int', (b,), field=field)),
        unit(2, 'return', right=out),
    ], [b, out])
    override = make_method('child', child, 'differentSyntheticName', (), 'int', False,
                           [unit(0, 'return', right=const(29))], [])
    units = [unit(0, 'assign', left=obj, right=Value('constant', child, value=None) if null else Expr('new', child))]
    if not null:
        units.append(unit(1, 'invoke', right=Expr('invoke', 'void', (obj,), method=ctor.symbol, mode='special')))
    units.append(unit(len(units), 'assign', left=declared, right=Expr('cast', base, (obj,))))
    units.append(unit(len(units), 'assign', left=out, right=Expr('invoke', 'int', (declared,), method=original.symbol, mode=mode)))
    units.append(unit(len(units), 'return', right=out))
    entry = make_method('entry', caller, 'entry', (), 'int', True, units, [obj, declared, out])
    def meta(m, attrs, token=None):
        return MethodMetadata(m.symbol.key, m.symbol.name, m.symbol.params, m.symbol.returns, attrs, token=token)
    metadata = ProgramMetadata((
        ClassMetadata(base, 'java.lang.Object', fields=(FieldMetadata('field:value', 'value', 'int'),),
                      methods=(meta(original, ('PUBLIC',), 7),)),
        ClassMetadata(child, base, methods=(meta(ctor, ('PUBLIC', 'CONSTRUCTOR')), meta(override, ('PUBLIC',), 7))),
        ClassMetadata(caller, 'java.lang.Object', methods=(meta(entry, ('PUBLIC', 'STATIC')),)),
    ))
    adapted = PySootAdapter().build(Program((ctor, original, override, entry), ()), metadata)
    return AngrLoader().load(adapted, entry_key='entry')


class CallTests(unittest.TestCase):
    def test_virtual_uses_cap_token_despite_different_synthetic_names(self):
        loaded = call_program()
        manager = loaded.project.factory.simgr(loaded.create_call_state()).run(n=50)
        self.assertFalse(manager.errored)
        self.assertFalse(manager.active)
        self.assertEqual(len(manager.deadended), 1)
        self.assertEqual(manager.deadended[0].solver.eval(manager.deadended[0].regs.invoke_return_value), 29)
        self.assertIn('child', loaded.readiness.reachable('entry'))

    def test_special_retains_declared_super_target_and_constructor_field(self):
        loaded = call_program('special')
        manager = loaded.project.factory.simgr(loaded.create_call_state()).run(n=50)
        self.assertFalse(manager.errored)
        self.assertEqual(len(manager.deadended), 1)
        self.assertEqual(manager.deadended[0].solver.eval(manager.deadended[0].regs.invoke_return_value), 17)
        self.assertNotIn('child', loaded.readiness.reachable('entry'))

    def test_null_instance_receiver_fault_is_not_an_unconstrained_return(self):
        loaded = call_program(null=True)
        manager = loaded.project.factory.simgr(loaded.create_call_state()).run(n=20)
        self.assertFalse(manager.deadended)
        self.assertEqual(len(manager.errored), 1)
        self.assertEqual(manager.errored[0].error.code, 'null_reference')


class RemainderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        x, y, out = local('x'), local('y'), local('out')
        body = method([
            unit(0, 'identity', left=x, right=Value('parameter', 'int', index=0)),
            unit(1, 'identity', left=y, right=Value('parameter', 'int', index=1)),
            unit(2, 'assign', left=out, right=Expr('binary', 'int', (x, y), 'rem')),
            unit(3, 'return', right=out),
        ], (x, y, out), params=('int', 'int'))
        cls.loaded = load(body)

    def test_signed_java_remainder_and_minimum_overflow_case(self):
        for x, y, expected in ((-7, 3, -1), (7, -3, 1), (-7, -3, -1), (-2147483648, -1, 0)):
            with self.subTest(x=x, y=y):
                m = self.loaded.project.factory.simgr(self.loaded.create_call_state(args=[x, y])).run(n=10)
                self.assertFalse(m.errored)
                self.assertEqual(len(m.deadended), 1)
                self.assertEqual(m.deadended[0].solver.eval(m.deadended[0].regs.invoke_return_value), expected & 0xffffffff)

    def test_symbolic_divisor_never_silently_drops_possible_zero(self):
        state = self.loaded.create_call_state(args=[7, SymbolicArgument('divisor')])
        manager = self.loaded.project.factory.simgr(state).run(n=10)
        self.assertEqual(len(manager.errored), 1)
        self.assertFalse(manager.deadended)
        error = manager.errored[0].error
        self.assertEqual(error.code, 'arithmetic_zero')
        self.assertTrue(state.solver.satisfiable(extra_constraints=[error.condition]))
        self.assertTrue(state.solver.satisfiable(extra_constraints=[~error.condition]))

    def test_symbolic_dividend_preserved_for_all_signed_inputs(self):
        state = self.loaded.create_call_state(args=[SymbolicArgument('dividend'), 8])
        manager = self.loaded.project.factory.simgr(state).run(n=10)
        self.assertFalse(manager.errored)
        end = manager.deadended[0]
        dividend = end.globals['cap2soot.inputs'][0]
        self.assertFalse(end.solver.satisfiable(extra_constraints=[end.regs.invoke_return_value != claripy.SMod(dividend, claripy.BVV(8, 32))]))


if __name__ == '__main__':
    unittest.main()
