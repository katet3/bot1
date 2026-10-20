"""Readable export; JSON retains the full CAP references and signatures."""
from .model import Constant, ValueType


def operand(value):
    if isinstance(value, Constant):
        return 'null' if value.value is None else str(value.value)
    return value.name


def reference(ref):
    if ref is None:
        return ''
    if ref.external:
        target = f'{ref.package_aid}/class_token_{ref.class_token}'
        if ref.member_token is not None:
            target += f'/token_{ref.member_token}'
    else:
        target = ref.package_aid
        if ref.class_offset is not None:
            target += f'/class_{ref.class_offset}'
        if ref.internal_offset is not None:
            target += f'/offset_{ref.internal_offset}'
        if ref.member_token is not None:
            target += f'/token_{ref.member_token}'
    return f'cp#{ref.cp_index}[{target}]'


def format_statement(stmt):
    values = ', '.join(operand(v) for v in stmt.operands)
    prefix = f'{stmt.result.name}:{stmt.result.type.value} = ' if stmt.result else ''
    typ = f'<{stmt.semantic_type.kind}>' if stmt.semantic_type else ''
    if stmt.op == 'load_local':
        body = f'local[{stmt.local_index}]'
    elif stmt.op == 'store_local':
        body = f'local[{stmt.local_index}] = {values}'
    else:
        ref = reference(stmt.reference)
        extras = ', '.join(x for x in (values, ref) if x)
        mode = f'.{stmt.mode}' if stmt.mode else ''
        body = f'{stmt.op}{mode}{typ}({extras})'
    traps = f' handlers={stmt.handler_indices}' if stmt.handler_indices else ''
    return f'{prefix}{body}{traps}'


def format_method(method):
    params = ', '.join(f'local[{a.slot}]:{a.declared_type.kind}' + (' this' if a.is_receiver else '')
                       for a in method.arguments)
    lines = [f'method {method.name} ({params}) -> {method.signature.returns.kind}',
             f'local_slots={method.local_slot_count}']
    outgoing = {b.id: [] for b in method.blocks}
    for edge in method.edges:
        outgoing[edge.source].append(edge)
    for block in method.blocks:
        params = ', '.join(f'{v.name}:{v.type.value}' for v in block.parameters)
        lines.append(f'B{block.id}({params}) @{block.start_offset}:')
        for stmt in block.statements:
            lines.append(f'  @{stmt.offset} {format_statement(stmt)}')
        term = block.terminator
        args = ', '.join(operand(v) for v in term.operands)
        relation = f'.{term.relation}' if term.relation else ''
        lines.append(f'  @{term.offset} {term.kind}{relation}({args})')
        for edge in outgoing[block.id]:
            values = ', '.join(operand(v) for v in edge.arguments)
            label = edge.kind
            if edge.kind == 'SWITCH_CASE':
                label += f' {edge.case_value}'
            if edge.kind == 'EXCEPTION':
                label += f' handler={edge.handler_index} argument=@exception'
            lines.append(f'    {label} -> B{edge.target}({values})')
    lines.extend(f'WARNING: {w}' for w in method.warnings)
    return '\n'.join(lines)
