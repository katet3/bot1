"""Build and validate stack IR; optionally check an existing CFG's normal edges."""
from collections import Counter, deque
from .model import *
from .lowering import lower

TERMINATORS = {Op.BRANCH, Op.GOTO, Op.SWITCH, Op.RETURN, Op.THROW}


class IRBuilder:
    def __init__(self, resolver=None):
        self.resolver = resolver

    def build(self, method, cfg=None):
        for name in ('max_stack','nargs','max_locals'):
            value=getattr(method,name,None)
            if not isinstance(value,int) or value<0:
                raise IRValidationError(f'Missing/invalid {name}; use methods_from_cap(cap_file)')
        handlers=getattr(method,'exception_handlers',None)
        if handlers is None:
            raise IRValidationError('Missing exception metadata; use methods_from_cap(cap_file)')
        handlers=tuple(handlers)
        if any(not isinstance(h,Handler) for h in handlers):
            raise IRValidationError('Handlers must use method-local offsets: jcvm_ir.Handler')
        instructions=method.instructions
        ops=[]; sizes={}; end=0
        for ins in instructions:
            if ins.offset!=end:
                raise IRValidationError(f'Noncontiguous instruction at {ins.offset}; expected {end}')
            try:
                op,size=lower(ins,self.resolver)
            except (KeyError,TypeError,IndexError) as exc:
                raise IRValidationError(f'Malformed operands at {ins.offset}: {ins.mnemonic}') from exc
            if end>=len(method.bytecodes) or method.bytecodes[end]!=ins.opcode:
                raise IRValidationError(f'Opcode/source mismatch at {end}')
            ops.append(op); sizes[end]=size; end+=size
        if end!=len(method.bytecodes):
            raise IRValidationError(f'Instruction coverage {end} != bytecode length {len(method.bytecodes)}')
        offsets={op.offset for op in ops}
        leaders={0} if ops else set()
        for i,op in enumerate(ops):
            for target in op.targets:
                if target not in offsets: raise IRValidationError(f'Invalid branch target {target} at {op.offset}')
                leaders.add(target)
            if op.op in TERMINATORS and i+1<len(ops): leaders.add(ops[i+1].offset)
        for h in handlers:
            if h.start not in offsets or h.end not in offsets|{end} or h.target not in offsets or h.start>=h.end:
                raise IRValidationError(f'Invalid exception range {h}')
            if self.resolver and h.catch_type_index:
                self.resolver.resolve(h.catch_type_index,(1,))
            leaders.update((h.start,h.target))
            if h.end<end: leaders.add(h.end)
        blocks=[]
        for op in ops:
            if op.offset in leaders: blocks.append(Block(len(blocks),op.offset,[]))
            blocks[-1].operations.append(op)
        by_offset={b.start:b.id for b in blocks}; edges=[]
        for i,b in enumerate(blocks):
            op=b.operations[-1]
            def edge(target,kind,case=None): edges.append(Edge(b.id,by_offset[target],kind,case))
            if op.op==Op.BRANCH:
                edge(op.targets[0],'CONDITIONAL_TRUE')
                if i+1==len(blocks): raise IRValidationError('Conditional branch falls off method')
                edge(blocks[i+1].start,'CONDITIONAL_FALSE')
            elif op.op==Op.GOTO: edge(op.targets[0],'GOTO')
            elif op.op==Op.SWITCH:
                edge(op.targets[0],'SWITCH_DEFAULT')
                for value,target in op.cases: edge(target,'SWITCH_CASE',value)
            elif op.op not in (Op.RETURN,Op.THROW):
                if i+1==len(blocks): raise IRValidationError(f'Method falls off end at {op.offset}')
                edge(blocks[i+1].start,'FALLTHROUGH')
            for hi,h in enumerate(handlers):
                if h.start<=b.start<h.end:
                    edges.append(Edge(b.id,by_offset[h.target],'EXCEPTION',handler_index=hi))
        ir=MethodIR(getattr(method,'name',str(method.token)),blocks,edges,handlers,
                    0 if blocks else None,method.max_stack,method.nargs,method.max_locals,
                    getattr(method,'signature',None))
        if not blocks: raise IRValidationError('Empty body: abstract/native methods must be filtered before IR')
        if ir.signature is None: ir.warnings.append('Method signature unavailable: return type is not checked')
        if cfg is not None: self._check_cfg(cfg,ir,method)
        self._verify_stacks(ir)
        return ir

    @staticmethod
    def _check_cfg(cfg,ir,method):
        # Exception regions may refine the supplied CFG. Never silently accept a different graph.
        actual=[[(i.offset,i.mnemonic,i.operands) for i in b.instructions] for b in cfg.blocks]
        source={i.offset:i for i in method.instructions}
        expected=[[(o.offset,o.mnemonic,source[o.offset].operands) for o in b.operations] for b in ir.blocks]
        if actual!=expected:
            raise IRValidationError('Input CFG blocks do not match normalized control flow')
        if not cfg.blocks or cfg.entry_block!=cfg.blocks[0].id:
            raise IRValidationError('Invalid input CFG entry')
        ids={b.id:b.start_offset for b in cfg.blocks}
        if len(ids)!=len(cfg.blocks): raise IRValidationError('Duplicate input CFG block IDs')
        try:
            old=Counter((ids[e.source],ids[e.target],e.edge_type.name) for e in cfg.edges if e.edge_type.name!='EXCEPTION')
        except KeyError as exc: raise IRValidationError('Invalid CFG edge endpoint') from exc
        new=Counter((ir.blocks[e.source].start,ir.blocks[e.target].start,
                     'SWITCH' if e.kind.startswith('SWITCH') else e.kind)
                    for e in ir.edges if e.kind!='EXCEPTION')
        if old!=new: raise IRValidationError('Input CFG normal edges differ from instruction semantics')
        # Exception edges come from the ordered handler table, never from unlabeled CFG edges.

    @staticmethod
    def _verify_stacks(ir):
        queue=deque([ir.entry]); ir.blocks[ir.entry].input_stack=()
        adjacency={b.id:[] for b in ir.blocks}
        for e in ir.edges: adjacency[e.source].append(e)
        # Check metadata even for unreachable instructions.
        for b in ir.blocks:
            for op in b.operations:
                if op.op in (Op.LOAD,Op.STORE,Op.INCREMENT):
                    if op.args[0]+op.value_type.slots>ir.nargs+ir.max_locals:
                        raise IRValidationError(f'Local index out of bounds at {op.offset}')
                if op.op==Op.RETURN and ir.signature:
                    if op.value_type.stack_kind!=ir.signature.returns.stack_kind:
                        raise IRValidationError(f'Return type mismatch at {op.offset}')
        while queue:
            b=ir.blocks[queue.popleft()]; stack=list(b.input_stack)
            def check_limit():
                if sum(2 if t=='int' else 1 for t in stack)>ir.max_stack:
                    raise IRValidationError(f'max_stack exceeded in B{b.id}')
            check_limit()
            for op in b.operations:
                if op.op==Op.STACK:
                    count=2 if op.args[0].endswith('2') else 1
                    tail=[]; slots=0
                    while slots<count and stack:
                        t=stack.pop();tail.insert(0,t);slots+=2 if t=='int' else 1
                    if slots!=count: raise IRValidationError(f'Invalid stack manipulation at {op.offset}')
                    if op.args[0].startswith('dup'): stack.extend(tail+tail)
                else:
                    expected=[t.stack_kind for t in op.pops]
                    if len(stack)<len(expected) or (expected and stack[-len(expected):]!=expected):
                        raise IRValidationError(f'Stack type/height mismatch at {op.offset}: {stack}, requires {expected}')
                    if expected: del stack[-len(expected):]
                    stack.extend(t.stack_kind for t in op.pushes)
                check_limit()
            b.output_stack=tuple(stack)
            for e in adjacency[b.id]:
                outgoing=('reference',) if e.kind=='EXCEPTION' else tuple(stack)
                target=ir.blocks[e.target]
                if target.input_stack is None:
                    target.input_stack=outgoing;queue.append(target.id)
                elif target.input_stack!=outgoing:
                    raise IRValidationError(f'Incompatible stack at merge B{target.id}: {target.input_stack} vs {outgoing}')
        for b in ir.blocks:
            if b.input_stack is None: ir.warnings.append(f'Unreachable block B{b.id}: stack not checked')
