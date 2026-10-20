"""Structural, value-use, type and definite local-initialization validation."""
from collections import deque

from .model import Constant, LoweringError, Value, ValueType

_BINARY = {'add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr'}
_NUMERIC = {ValueType.SHORT, ValueType.INT}


def require(condition, message):
    if not condition:
        raise LoweringError(message)


def validate(method):
    blocks = {b.id: b for b in method.blocks}
    require(len(blocks) == len(method.blocks) and method.entry in blocks, 'Invalid block IDs or entry')
    require(not blocks[method.entry].parameters, 'Entry must have no block parameters')
    require(method.local_slot_count >= 0, 'Negative local slot count')
    edges_by_block = {b.id: [] for b in method.blocks}
    for edge in method.edges:
        require(edge.source in blocks and edge.target in blocks, 'Invalid edge endpoint')
        edges_by_block[edge.source].append(edge)
    occupied = set()
    for arg in method.arguments:
        typ = ValueType.of(arg.declared_type)
        slots = set(range(arg.slot, arg.slot + typ.slots))
        require(arg.slot >= 0 and arg.slot + typ.slots <= method.local_slot_count,
                'Argument outside local slot array')
        require(not occupied & slots, 'Overlapping argument slots')
        occupied.update(slots)
        require(not arg.is_receiver or (arg.slot == 0 and typ is ValueType.REFERENCE), 'Invalid receiver')
    declared = tuple(a.declared_type for a in method.arguments if not a.is_receiver)
    require(declared == method.signature.parameters, 'Arguments disagree with signature')
    require(sum(a.is_receiver for a in method.arguments) <= 1, 'Multiple receivers')
    all_names = set()
    all_stmt_ids = set()
    starts = {b.start_offset: b.id for b in method.blocks}
    require(len(starts) == len(blocks), 'Duplicate block start offsets')
    for hi, handler in enumerate(method.handlers):
        require(handler.start < handler.end and handler.target in starts, f'Invalid handler {hi}')
    for block in method.blocks:
        require(block.source_offsets and block.start_offset == block.source_offsets[0], 'Missing source locations')
        require(tuple(sorted(set(block.source_offsets))) == block.source_offsets, 'Source offsets out of order')
        known = {}
        for value in block.parameters:
            require(value.name not in all_names, f'Duplicate value {value.name}')
            all_names.add(value.name)
            known[value.name] = value.type

        def use(value):
            if isinstance(value, Constant):
                if value.type is ValueType.REFERENCE:
                    require(value.value is None, 'Only null may be an immediate reference')
                else:
                    bits = value.type.bits
                    require(isinstance(value.value, int) and -(1 << (bits-1)) <= value.value < (1 << (bits-1)),
                            'Integer constant is outside its signed width')
            elif isinstance(value, Value):
                require(known.get(value.name) == value.type,
                        f'B{block.id}: undefined, forward or mistyped value {value.name}')
            else:
                raise LoweringError('Invalid operand')

        for stmt in block.statements:
            require(stmt.id not in all_stmt_ids, f'Duplicate statement {stmt.id}')
            all_stmt_ids.add(stmt.id)
            require(stmt.offset in block.source_offsets, 'Statement lost source offset')
            for value in stmt.operands:
                use(value)
            _statement_types(stmt, method.local_slot_count)
            expected_handlers = tuple(i for i, h in enumerate(method.handlers)
                                      if h.start <= stmt.offset < h.end) if stmt.may_throw else ()
            require(stmt.handler_indices == expected_handlers, 'Invalid statement handler ordering')
            if stmt.result:
                require(stmt.result.name not in all_names, f'Redefinition of {stmt.result.name}')
                all_names.add(stmt.result.name)
                known[stmt.result.name] = stmt.result.type
        term = block.terminator
        require(term.offset in block.source_offsets, 'Terminator lost source offset')
        for value in term.operands:
            use(value)
        normal = [e for e in edges_by_block[block.id] if e.kind != 'EXCEPTION']
        kinds = [e.kind for e in normal]
        types = tuple(v.type for v in term.operands)
        if term.kind == 'branch':
            require(sorted(kinds) == ['CONDITIONAL_FALSE', 'CONDITIONAL_TRUE'], 'Invalid branch edges')
            require(len(types) == 2 and types[0] == types[1], 'Invalid branch operands')
            require(term.relation in ('eq','ne','lt','le','gt','ge'), 'Invalid branch relation')
            require(types[0] is not ValueType.REFERENCE or term.relation in ('eq','ne'), 'Ordered reference comparison')
        elif term.kind == 'switch':
            require(types in ((ValueType.SHORT,), (ValueType.INT,)), 'Invalid switch selector')
            require(kinds.count('SWITCH_DEFAULT') == 1 and set(kinds) <= {'SWITCH_CASE','SWITCH_DEFAULT'}, 'Invalid switch edges')
            keys = [e.case_value for e in normal if e.kind == 'SWITCH_CASE']
            require(len(keys) == len(set(keys)), 'Duplicate case value')
            for key in keys:
                use(Constant(key, types[0]))
        elif term.kind == 'goto':
            require(not types and len(normal) == 1 and normal[0].kind in ('GOTO','FALLTHROUGH'), 'Invalid goto')
        elif term.kind == 'return':
            expected = () if method.signature.returns.kind == 'void' else (ValueType.of(method.signature.returns),)
            require(types == expected and not normal, 'Invalid return type or successor')
        elif term.kind == 'throw':
            require(types == (ValueType.REFERENCE,) and not normal, 'Invalid throw')
        else:
            raise LoweringError(f'Unknown terminator {term.kind}')
        traps = tuple(i for i,h in enumerate(method.handlers) if h.start <= term.offset < h.end)
        require(term.handler_indices == (traps if term.kind == 'throw' else ()), 'Invalid throw handler ordering')
        exception_indices = []
        for edge in edges_by_block[block.id]:
            target = blocks[edge.target]
            if edge.kind == 'EXCEPTION':
                require(edge.handler_index is not None and 0 <= edge.handler_index < len(method.handlers), 'Invalid exception edge')
                handler = method.handlers[edge.handler_index]
                require(handler.start <= block.start_offset < handler.end and target.start_offset == handler.target,
                        'Exception edge disagrees with handler')
                require(not edge.arguments and tuple(v.type for v in target.parameters) == (ValueType.REFERENCE,),
                        'Exception edge must deliver one runtime exception reference')
                exception_indices.append(edge.handler_index)
            else:
                for value in edge.arguments:
                    use(value)
                require(tuple(v.type for v in edge.arguments) == tuple(v.type for v in target.parameters),
                        f'B{block.id} -> B{target.id}: invalid block arguments')
        expected_indices = [i for i,h in enumerate(method.handlers) if h.start <= block.start_offset < h.end]
        require(exception_indices == expected_indices, 'Missing or reordered conservative exception edges')
    _validate_locals(method, blocks, edges_by_block)


def _statement_types(s, capacity):
    types = tuple(v.type for v in s.operands)
    result = s.result.type if s.result else None
    semantic = ValueType.of(s.semantic_type) if s.semantic_type and s.semantic_type.kind != 'void' else None
    if s.op in ('load_local', 'store_local'):
        require(s.local_index is not None and semantic is not None, 'Missing local metadata')
        require(0 <= s.local_index and s.local_index + semantic.slots <= capacity, 'Local access out of bounds')
        if s.op == 'load_local':
            require(not types and result == semantic, 'Invalid local load')
        else:
            require(types == (semantic,) and result is None, 'Invalid local store')
    elif s.op in _BINARY:
        require(semantic in _NUMERIC and types == (semantic,semantic) and result == semantic, 'Invalid arithmetic types')
        require(s.op != 'ushr' or semantic is ValueType.INT, 'Short ushr must be widened to int before shifting')
    elif s.op == 'neg':
        require(semantic in _NUMERIC and types == (semantic,) and result == semantic, 'Invalid negation')
    elif s.op == 'convert':
        conversions = {'s2b':(ValueType.SHORT,ValueType.SHORT), 's2i':(ValueType.SHORT,ValueType.INT),
                       'i2b':(ValueType.INT,ValueType.SHORT), 'i2s':(ValueType.INT,ValueType.SHORT)}
        require(s.mode in conversions, 'Unknown conversion')
        src,dst = conversions[s.mode]
        require(types == (src,) and result == dst, 'Invalid conversion types')
    elif s.op == 'compare_signed':
        require(types == (ValueType.INT,ValueType.INT) and result is ValueType.SHORT, 'Invalid icmp')
    elif s.op in ('load_field','store_field'):
        require(s.reference is not None and s.reference.field_type == s.semantic_type, 'Missing/mismatched field reference')
        require(s.mode in ('static','object'), 'Field receiver must be explicit')
        require(s.reference.tag == (5 if s.mode == 'static' else 2), 'Incorrect field reference tag')
        receiver = () if s.mode == 'static' else (ValueType.REFERENCE,)
        if s.op == 'load_field':
            require(types == receiver and result == semantic, 'Invalid field load')
        else:
            require(types == receiver+(semantic,) and result is None, 'Invalid field store')
    elif s.op in ('array_load','array_store'):
        prefix = (ValueType.REFERENCE,ValueType.SHORT)
        require(semantic is not None, 'Array element type missing')
        if s.op == 'array_load':
            require(types == prefix and result == semantic, 'Invalid array load')
        else:
            require(types == prefix+(semantic,) and result is None, 'Invalid array store')
    elif s.op == 'array_length':
        require(types == (ValueType.REFERENCE,) and result is ValueType.SHORT, 'Invalid array length')
    elif s.op == 'new_object':
        require(not types and result is ValueType.REFERENCE and s.reference is not None and s.reference.tag == 1,
                'Invalid object allocation')
    elif s.op == 'new_array':
        require(types == (ValueType.SHORT,) and result is ValueType.REFERENCE, 'Invalid array allocation')
        require(s.mode in ('boolean','byte','short','int','reference'), 'Invalid array component type')
        if s.mode == 'reference':
            require(s.reference is not None and s.reference.tag == 1, 'Missing reference-array class')
    elif s.op == 'call':
        require(s.reference is not None and s.reference.signature is not None, 'Missing call signature')
        require(s.mode in ('invokevirtual','invokespecial','invokestatic'), 'Invalid invocation kind')
        sig = s.reference.signature
        expected = (() if s.mode == 'invokestatic' else (ValueType.REFERENCE,)) + tuple(ValueType.of(t) for t in sig.parameters)
        output = None if sig.returns.kind == 'void' else ValueType.of(sig.returns)
        require(types == expected and result == output and s.semantic_type == sig.returns, 'Invalid call operands/result')
    else:
        raise LoweringError(f'Unknown statement {s.op}')
    must_throw = s.op in {'load_field','store_field','array_load','array_store','array_length','new_object','new_array','call','div','rem'}
    require(s.may_throw == must_throw, 'Incorrect may_throw annotation')


def _store(state, index, kind):
    """Invalidate overlapping two-word locals, then write a logical value."""
    data = list(state)
    size = 2 if kind == 'int' else 1
    for slot in range(index, index+size):
        if data[slot] == 'int' and slot+1 < len(data):
            data[slot+1] = None
        if data[slot] == 'tail' and slot > 0:
            data[slot-1] = None
        data[slot] = None
    data[index] = kind
    if size == 2:
        data[index+1] = 'tail'
    return tuple(data)


def _validate_locals(method, blocks, outgoing):
    initial = (None,) * method.local_slot_count
    for arg in method.arguments:
        initial = _store(initial, arg.slot, ValueType.of(arg.declared_type).value)
    incoming = {key: None for key in blocks}
    incoming[method.entry] = initial
    queue = deque([method.entry])

    def merge(target, state):
        old = incoming[target]
        new = state if old is None else tuple(a if a == b else None for a,b in zip(old,state))
        if old != new:
            incoming[target] = new
            queue.append(target)

    def exception_states(indices, state):
        for hi in indices:
            h = method.handlers[hi]
            target = next(b.id for b in method.blocks if b.start_offset == h.target)
            merge(target, state)

    while queue:
        bid = queue.popleft()
        block = blocks[bid]
        state = incoming[bid]
        for stmt in block.statements:
            # Handler sees locals as they were at the throwing instruction,
            # not after the remainder of the block has executed.
            exception_states(stmt.handler_indices, state)
            if stmt.op == 'store_local':
                state = _store(state, stmt.local_index, stmt.operands[0].type.value)
        exception_states(block.terminator.handler_indices, state)
        for edge in outgoing[bid]:
            if edge.kind != 'EXCEPTION':
                merge(edge.target, state)
    for bid, block in blocks.items():
        state = incoming[bid]
        # A conservative exception edge may come from a nonthrowing block.
        # Such a handler has no executable predecessor in the refined model.
        if state is None:
            continue
        for stmt in block.statements:
            if stmt.op == 'load_local':
                index = stmt.local_index
                typ = stmt.result.type
                require(state[index] == typ.value and (typ is not ValueType.INT or state[index+1] == 'tail'),
                        f'B{bid} @{stmt.offset}: uninitialized/incompatible local[{index}]')
            elif stmt.op == 'store_local':
                state = _store(state, stmt.local_index, stmt.operands[0].type.value)
