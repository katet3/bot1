"""Eliminate the JCVM operand stack without reordering effects or duplicating reads."""
from __future__ import annotations

from jcvm_ir import Op, Type
from .model import (Argument, Block, Constant, Edge, LoweringError, Method,
                    Statement, Terminator, Value, ValueType)

_ENDS = {Op.BRANCH, Op.GOTO, Op.SWITCH, Op.RETURN, Op.THROW}
_THROWS = {Op.FIELD_LOAD, Op.FIELD_STORE, Op.ARRAY_LOAD, Op.ARRAY_STORE,
           Op.ARRAY_LENGTH, Op.NEW, Op.NEW_ARRAY, Op.CALL, Op.CHECKCAST}


class JVMLikeIRBuilder:
    def build(self, source) -> Method:
        if source.signature is None:
            raise LoweringError('Method signature is required; use methods_from_cap()')
        if not source.blocks or source.entry is None:
            raise LoweringError('Empty method body is unsupported')
        blocks = {b.id: b for b in source.blocks}
        if len(blocks) != len(source.blocks) or source.entry not in blocks:
            raise LoweringError('Invalid or duplicate block IDs')
        if any(b.input_stack is None or b.output_stack is None for b in source.blocks):
            raise LoweringError('Unverified/unreachable block: stack types are required for every block')
        if blocks[source.entry].input_stack:
            raise LoweringError('The method entry stack must be empty')
        capacity = source.nargs + source.max_locals
        arguments = self._arguments(source)
        parameters = {
            b.id: tuple(Value(f'%b{b.id}_p{i}', ValueType(kind))
                        for i, kind in enumerate(b.input_stack))
            for b in source.blocks
        }
        outgoing = {b.id: [] for b in source.blocks}
        for edge in source.edges:
            if edge.source not in blocks or edge.target not in blocks:
                raise LoweringError('Unknown edge endpoint')
            outgoing[edge.source].append(edge)
        output_blocks = []
        output_edges = []
        for block in source.blocks:
            lowered, remaining = self._block(block, parameters[block.id], source, arguments)
            output_blocks.append(lowered)
            expected = tuple(block.output_stack)
            if tuple(v.type.value for v in remaining) != expected:
                raise LoweringError(f'B{block.id}: output stack disagrees with jcvm_ir')
            for edge in outgoing[block.id]:
                vals = () if edge.kind == 'EXCEPTION' else tuple(remaining)
                output_edges.append(Edge(edge.source, edge.target, edge.kind, vals,
                                         edge.case_value, edge.handler_index))
        result = Method(source.name, source.entry, source.signature, arguments, capacity,
                        tuple(output_blocks), tuple(output_edges), tuple(source.handlers),
                        tuple(source.warnings))
        result.validate()
        return result

    @staticmethod
    def _arguments(source):
        words = sum(t.slots for t in source.signature.parameters)
        receiver_words = source.nargs - words
        if receiver_words not in (0, 1):
            raise LoweringError('Signature and nargs disagree about the receiver')
        args = [Argument(0, Type('reference'), True)] if receiver_words else []
        slot = receiver_words
        for typ in source.signature.parameters:
            if typ.kind == 'void':
                raise LoweringError('Void parameter')
            args.append(Argument(slot, typ))
            slot += typ.slots
        return tuple(args)

    def _block(self, block, parameters, method, arguments):
        if not block.operations:
            raise LoweringError(f'Empty block B{block.id}')
        stack = list(parameters)
        statements = []
        term = None
        serial = 0
        normal_edges = [e for e in method.edges if e.source == block.id and e.kind != 'EXCEPTION']
        by_id = {b.id: b for b in method.blocks}
        receiver = next((a for a in arguments if a.is_receiver), None)

        def traps(offset):
            return tuple(i for i, h in enumerate(method.handlers) if h.start <= offset < h.end)

        def emit(op, source_op, operands=(), result_type=None, **kwargs):
            nonlocal serial
            sid = f'b{block.id}_{serial}'
            serial += 1
            value = Value('%' + sid, result_type) if result_type else None
            throwing = kwargs.get('may_throw', False)
            statements.append(Statement(sid, source_op.offset, op, tuple(operands), value,
                                        handler_indices=traps(source_op.offset) if throwing else (),
                                        **kwargs))
            return value

        def pop_types(op):
            n = len(op.pops)
            values = stack[-n:] if n else []
            if len(stack) < n or tuple(v.type for v in values) != tuple(ValueType.of(t) for t in op.pops):
                raise LoweringError(f'B{block.id} @{op.offset}: invalid stack operands for {op.op}')
            if n:
                del stack[-n:]
            return values

        def push(op, value):
            if len(op.pushes) != 1 or value.type != ValueType.of(op.pushes[0]):
                raise LoweringError(f'@{op.offset}: invalid result type for {op.op}')
            stack.append(value)

        for op in block.operations:
            if term is not None:
                raise LoweringError(f'Instructions after terminator in B{block.id}')
            if op.op == Op.STACK:
                name = op.args[0]
                if name not in ('dup', 'dup2', 'pop', 'pop2'):
                    raise LoweringError(f'Unsupported stack operation {name}')
                count = 2 if name.endswith('2') else 1
                values = []
                words = 0
                while stack and words < count:
                    v = stack.pop()
                    values.insert(0, v)
                    words += v.type.slots
                if words != count:
                    raise LoweringError(f'@{op.offset}: stack manipulation splits an int or underflows')
                if name.startswith('dup'):
                    # Alias immutable values: never repeat allocation, load or call.
                    stack.extend(values + values)
                continue
            values = pop_types(op)
            if op.op == Op.NOP:
                continue
            if op.op == Op.CONST:
                value = Constant(op.args[0], ValueType.of(op.value_type))
                push(op, value)
            elif op.op == Op.LOAD:
                value = emit('load_local', op, result_type=ValueType.of(op.value_type),
                             local_index=op.args[0], semantic_type=op.value_type)
                push(op, value)
            elif op.op == Op.STORE:
                emit('store_local', op, values, local_index=op.args[0], semantic_type=op.value_type)
            elif op.op == Op.INCREMENT:
                typ = ValueType.of(op.value_type)
                previous = emit('load_local', op, result_type=typ, local_index=op.args[0],
                                semantic_type=op.value_type)
                updated = emit('add', op, (previous, Constant(op.args[1], typ)), result_type=typ,
                               semantic_type=op.value_type)
                emit('store_local', op, (updated,), local_index=op.args[0], semantic_type=op.value_type)
            elif op.op == Op.BINARY and op.args[0] == 'ushr' and op.value_type.kind == 'short':
                # JCVM sushr is NOT a 16-bit logical shift: sign-extend to int,
                # use Java's 32-bit logical shift, then narrow to short (7.5.107).
                left = emit('convert', op, (values[0],), result_type=ValueType.INT,
                            semantic_type=Type('int'), mode='s2i')
                right = emit('convert', op, (values[1],), result_type=ValueType.INT,
                             semantic_type=Type('int'), mode='s2i')
                shifted = emit('ushr', op, (left, right), result_type=ValueType.INT,
                               semantic_type=Type('int'))
                value = emit('convert', op, (shifted,), result_type=ValueType.SHORT,
                             semantic_type=Type('short'), mode='i2s')
                push(op, value)
            elif op.op in (Op.BINARY, Op.UNARY):
                value = emit(op.args[0], op, values, result_type=ValueType.of(op.value_type),
                             semantic_type=op.value_type,
                             may_throw=op.op == Op.BINARY and op.args[0] in ('div', 'rem'))
                push(op, value)
            elif op.op == Op.CONVERT:
                mode = op.args[0]
                if mode not in ('s2b', 's2i', 'i2b', 'i2s'):
                    raise LoweringError(f'Unsupported conversion {mode}')
                value = emit('convert', op, values, result_type=ValueType.of(op.pushes[0]),
                             semantic_type=op.value_type, mode=mode)
                push(op, value)
            elif op.op == Op.COMPARE:
                value = emit('compare_signed', op, values, result_type=ValueType.SHORT,
                             semantic_type=Type('short'))
                push(op, value)
            elif op.op in _THROWS:
                operands = list(values)
                mode = None
                if op.op in (Op.FIELD_LOAD, Op.FIELD_STORE):
                    mode = op.args[0]
                    if mode == 'this':
                        if receiver is None:
                            raise LoweringError('Implicit this used in a static method')
                        obj = emit('load_local', op, result_type=ValueType.REFERENCE,
                                   local_index=0, semantic_type=Type('reference'))
                        operands.insert(0, obj)
                        mode = 'object'
                    if mode not in ('object', 'static'):
                        raise LoweringError(f'Invalid field access mode {mode}')
                elif op.op == Op.CALL:
                    mode = op.args[0]
                elif op.op == Op.NEW_ARRAY:
                    mode = op.args[0] if op.args else 'reference'
                result_type = ValueType.of(op.pushes[0]) if op.pushes else None
                value = emit(op.op.value, op, operands, result_type=result_type,
                             semantic_type=op.value_type, reference=op.reference,
                             mode=mode, may_throw=True)
                if value:
                    push(op, value)
            elif op.op in _ENDS:
                relation = None
                kind = op.op.value
                if op.op == Op.BRANCH:
                    relation, mode = op.args
                    if mode in ('zero', 'null'):
                        values.append(Constant(None if mode == 'null' else 0,
                                               ValueType.REFERENCE if mode == 'null' else ValueType.SHORT))
                    elif mode != 'pair':
                        raise LoweringError(f'Invalid branch mode {mode}')
                term = Terminator(op.offset, kind, tuple(values), relation,
                                  traps(op.offset) if op.op == Op.THROW else ())
                self._check_targets(op, normal_edges, by_id)
            else:
                raise LoweringError(f'Unsupported JCVM IR operation {op.op}')
        if term is None:
            if len(normal_edges) != 1 or normal_edges[0].kind != 'FALLTHROUGH':
                raise LoweringError(f'B{block.id}: expected one fallthrough edge')
            term = Terminator(block.operations[-1].offset, 'goto')
        return Block(block.id, block.start, parameters, tuple(statements), term,
                     tuple(o.offset for o in block.operations)), tuple(stack)

    @staticmethod
    def _check_targets(op, edges, by_id):
        from collections import Counter
        expected = []
        if op.op == Op.BRANCH:
            true = [e for e in edges if e.kind == 'CONDITIONAL_TRUE']
            false = [e for e in edges if e.kind == 'CONDITIONAL_FALSE']
            if len(edges) != 2 or len(true) != 1 or len(false) != 1:
                raise LoweringError('A branch must have true and false edges')
            if by_id[true[0].target].start != op.targets[0]:
                raise LoweringError('Conditional target differs from its edge')
            return
        if op.op == Op.GOTO:
            expected = [('GOTO', op.targets[0], None)]
        elif op.op == Op.SWITCH:
            expected = [('SWITCH_DEFAULT', op.targets[0], None)]
            expected += [('SWITCH_CASE', target, value) for value, target in op.cases]
        actual = [(e.kind, by_id[e.target].start, e.case_value) for e in edges]
        if Counter(expected) != Counter(actual):
            raise LoweringError(f'@{op.offset}: edges disagree with {op.op.value}')
