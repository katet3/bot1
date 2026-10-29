"""Project-local Soot translation hooks for the checked CAP heap.

The ordinary angr statement/call/branch machinery is reused. No global angr
registry is patched and no stock Java heap operation is executed here.
"""
from types import SimpleNamespace

from angr import claripy
from angr.engines.soot import expressions, statements
from angr.engines.soot.expressions.invoke import InvokeBase
from angr.engines.soot.values import translate_value
from archinfo.arch_soot import SootArgument

from .errors import HeapError
from .heap_types import is_reference_type
from .calls import invocation_mode


class CAPInvoke(InvokeBase):
    def _execute(self):
        backend = self.state.project.loader.main_object
        self.receiver = None
        if invocation_mode(self.expr) != 'static':
            self.receiver = evaluate(self.expr.base, self.state).expr
            self.state.cap_heap.validate_reference(self.receiver, self.expr.class_name, nullable=False)
        self.target = backend.cap_readiness.call_resolver.resolve(self.expr,
            None if self.receiver is None else self.receiver.type)
        if self.target.key is not None:
            backend.cap_readiness.require(self.target.key)
            self.method = backend.cap_index.descriptors[self.target.key]
        self.args = [] if self.target.static else [SootArgument(self.receiver, self.target.owner, is_this_ref=True)]
        self.values = [self.state.cap_heap.normalize(evaluate(arg, self.state).expr, ty)
                       for arg, ty in zip(self.expr.args, self.target.params, strict=True)]
        self.args.extend(SootArgument(v, ty) for v, ty in zip(self.values, self.target.params, strict=True))


def evaluate(node, state):
    name, heap = type(node).__name__, state.cap_heap
    value = lambda child: evaluate(child, state).expr
    if name == 'SootBinopExpr' and node.op == 'rem':
        left, right = value(node.value1), value(node.value2)
        heap._require(right != 0, 'arithmetic_zero', 'Possible ArithmeticException: remainder by zero')
        return SimpleNamespace(expr=claripy.SMod(left, right))
    if name == "SootNewExpr":
        return SimpleNamespace(expr=heap.new_object(node.type))
    if name == "SootNewArrayExpr":
        return SimpleNamespace(expr=heap.new_array(node.base_type, value(node.size)))
    if name == "SootInstanceFieldRef":
        field, owner = node.field
        return SimpleNamespace(expr=heap.read_field(value(node.base), owner, field, node.type))
    if name == "SootArrayRef":
        ref = value(node.base)
        heap.validate_reference(ref, node.base.type, nullable=False)
        return SimpleNamespace(expr=heap.read_array(ref, value(node.index)))
    if name == "SootLengthExpr":
        return SimpleNamespace(expr=heap.array_length(value(node.value)))
    if name == "SootCastExpr" and is_reference_type(node.cast_type):
        return SimpleNamespace(expr=heap.cast_reference(value(node.value), node.cast_type))
    if name == "SootConditionExpr" and is_reference_type(node.value1.type):
        if node.op not in {"eq", "ne"}:
            raise HeapError("reference_comparison", "Only reference equality/inequality is supported")
        left, right = value(node.value1), value(node.value2)
        heap.validate_reference(left)
        heap.validate_reference(right)
        same = left == right
        result = same if node.op == "eq" else not same
        return SimpleNamespace(expr=claripy.true() if result else claripy.false())
    # Instantiate translators locally to make recursive expressions use this
    # evaluator too. Invocation remains an InvokeBase for the engine protocol.
    kind = name.removeprefix("Soot").removesuffix("Expr")
    translator = CAPInvoke if invocation_mode(node) else getattr(expressions, "SimSootExpr_" + kind, None)
    allowed = {"SootLocal", "SootIntConstant", "SootNullConstant", "SootParamRef", "SootThisRef",
               "SootConditionExpr", "SootBinopExpr", "SootCastExpr", "SootStaticInvokeExpr",
               "SootSpecialInvokeExpr", "SootVirtualInvokeExpr", "SootInterfaceInvokeExpr"}
    if name not in allowed or translator is None:
        raise HeapError("expression", f"Execution model not enabled for {name}")
    translated = translator(node, state)
    translated._translate_expr = lambda child: evaluate(child, state)
    translated.process()
    if translated.expr is None:
        raise HeapError("undefined_value", f"Uninitialized local/parameter: {node}")
    return translated


class CAPAssign(statements.SimSootStmt_Assign):
    def _execute(self):
        target = self.stmt.left_op
        source = evaluate(self.stmt.right_op, self.state)
        name = type(target).__name__
        if isinstance(source, InvokeBase):
            if name != "SootLocal":
                raise HeapError("call_target", "Invocation result must be assigned to a local")
            self._add_invoke_target(source, translate_value(target, self.state))
            return
        value, heap = source.expr, self.state.cap_heap
        if name == "SootLocal":
            if is_reference_type(target.type):
                heap.validate_reference(value, target.type)
            self.state.memory.store(translate_value(target, self.state), value)
        elif name == "SootInstanceFieldRef":
            field, owner = target.field
            heap.write_field(evaluate(target.base, self.state).expr, owner, field, target.type, value)
        elif name == "SootArrayRef":
            ref = evaluate(target.base, self.state).expr
            heap.validate_reference(ref, target.base.type, nullable=False)
            heap.write_array(ref, evaluate(target.index, self.state).expr, value)
        else:
            raise HeapError("assignment", f"Unsupported assignment target: {name}")


def translate_stmt(stmt, state):
    name = type(stmt).__name__.removesuffix("Stmt")
    cls = CAPAssign if name == "Assign" else getattr(statements, "SimSootStmt_" + name, None)
    if cls is None:
        return None
    translated = cls(stmt, state)
    translated._translate_expr = lambda node: evaluate(node, state)
    translated.process()
    if isinstance(translated, statements.SimSootStmt_Return):
        ret_type = state.project.loader.main_object.get_soot_method(state.addr.method).ret
        translated.return_value = state.cap_heap.normalize(translated.return_value, ret_type)
    return translated
