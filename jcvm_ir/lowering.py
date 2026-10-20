"""Normalize supported JCVM instructions, retaining fixed-width semantics."""
import re
from .model import Op, Operation, Type, SHORT, INT, REF, VOID, IRValidationError


TYPES = {'s': SHORT, 'i': INT, 'a': REF, 'b': Type('byte')}
RELATIONS = {'eq':'eq', 'ne':'ne', 'lt':'lt', 'le':'le', 'gt':'gt', 'ge':'ge'}


def lower(ins, resolver):
    m, operands = ins.mnemonic, ins.operands
    args = tuple(operands) if isinstance(operands, (list, tuple)) else ()

    def one():
        if len(args) != 1 or not isinstance(args[0], int):
            raise IRValidationError(f'{m}: expected one integer operand')
        return args[0]

    def emit(op, typ=VOID, values=(), pops=(), pushes=(), ref=None, targets=(), cases=(), size=1):
        return Operation(ins.offset, m, op, typ, tuple(values), ref, tuple(pops),
                         tuple(pushes), tuple(targets), tuple(cases)), size

    def resolve(tags):
        if resolver is None:
            raise IRValidationError(f'{m}: ReferenceResolver is required')
        return resolver.resolve(one(), tags)

    if m == 'nop': return emit(Op.NOP)
    if m == 'aconst_null': return emit(Op.CONST, REF, (None,), pushes=(REF,))
    match = re.fullmatch(r'([si])const_(m1|[0-5])', m)
    if match:
        typ = TYPES[match[1]]
        return emit(Op.CONST, typ, (-1 if match[2]=='m1' else int(match[2]),), pushes=(typ,))
    if m in ('bspush','sspush','bipush','sipush','iipush'):
        typ = SHORT if m in ('bspush','sspush') else INT
        width = {'bspush':1,'sspush':2,'bipush':1,'sipush':2,'iipush':4}[m]
        value = one()
        if not -(1 << (width*8-1)) <= value < (1 << (width*8-1)):
            raise IRValidationError(f'{m}: invalid signed immediate {value}')
        return emit(Op.CONST, typ, (value,), pushes=(typ,), size=1+width)
    match = re.fullmatch(r'([asi])(load|store)(?:_([0-3]))?', m)
    if match:
        typ = TYPES[match[1]]
        index = int(match[3]) if match[3] else one()
        if not 0 <= index <= 255: raise IRValidationError('Invalid local index')
        load = match[2]=='load'
        return emit(Op.LOAD if load else Op.STORE, typ, (index,),
                    pops=() if load else (typ,), pushes=(typ,) if load else (),
                    size=1 if match[3] else 2)
    if m in ('pop','pop2','dup','dup2'):
        return emit(Op.STACK, values=(m,))
    match = re.fullmatch(r'([si])(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)', m)
    if match:
        typ = TYPES[match[1]]
        right = typ
        return emit(Op.BINARY, typ, (match[2],), pops=(typ,right), pushes=(typ,))
    if m in ('sneg','ineg'):
        typ=TYPES[m[0]]
        return emit(Op.UNARY, typ, ('neg',), pops=(typ,), pushes=(typ,))
    if m in ('s2b','s2i','i2b','i2s'):
        src, dst = TYPES[m[0]], TYPES[m[2]]
        return emit(Op.CONVERT, dst, (m,), pops=(src,), pushes=(SHORT if m[2]=='b' else dst,))
    if m == 'icmp': return emit(Op.COMPARE, SHORT, ('signed',), pops=(INT,INT), pushes=(SHORT,))
    if m in ('sinc','iinc'):
        if len(args)!=2 or not 0<=args[0]<=255 or not -128<=args[1]<=127:
            raise IRValidationError(f'{m}: expected local index and signed byte increment')
        return emit(Op.INCREMENT, TYPES[m[0]], args, size=3)
    match = re.fullmatch(r'(get|put)(field|static)_([absi])(_this|_w)?', m)
    if match:
        load, static = match[1]=='get', match[2]=='static'
        implicit = match[4]=='_this'
        if static and match[4]: raise IRValidationError(f'Unsupported instruction {m}')
        ref = resolve((5,) if static else (2,))
        typ = TYPES[match[3]]
        allowed = {'a': ('reference','boolean[]','byte[]','short[]','int[]','reference[]'),
                   'b': ('byte','boolean'), 's': ('short',), 'i': ('int',)}
        if ref.field_type.kind not in allowed[match[3]]:
            raise IRValidationError(f'{m}: field type mismatch at cp#{ref.cp_index}')
        obj = () if static or implicit else (REF,)
        pops = obj if load else obj+(typ,)
        width = 2 if static or match[4]=='_w' else 1
        if not 0 <= one() < (1 << (8*width)): raise IRValidationError('Field index out of range')
        return emit(Op.FIELD_LOAD if load else Op.FIELD_STORE, ref.field_type,
                    ('static' if static else 'this' if implicit else 'object',),
                    pops=pops, pushes=(typ,) if load else (), ref=ref, size=1+width)
    match = re.fullmatch(r'([absi])a(load|store)', m)
    if match:
        typ = TYPES[match[1]]; load = match[2]=='load'
        return emit(Op.ARRAY_LOAD if load else Op.ARRAY_STORE, typ,
                    pops=(REF,SHORT) if load else (REF,SHORT,typ),
                    pushes=(typ,) if load else ())
    if m == 'arraylength': return emit(Op.ARRAY_LENGTH, SHORT, pops=(REF,), pushes=(SHORT,))
    if m == 'new': return emit(Op.NEW, REF, ref=resolve((1,)), pushes=(REF,), size=3)
    if m == 'newarray':
        kinds={10:'boolean',11:'byte',12:'short',13:'int'}
        if one() not in kinds: raise IRValidationError('Invalid newarray type')
        return emit(Op.NEW_ARRAY, Type(kinds[one()]+'[]'), (kinds[one()],), pops=(SHORT,), pushes=(REF,), size=2)
    if m == 'anewarray':
        return emit(Op.NEW_ARRAY, Type('reference[]'), ref=resolve((1,)), pops=(SHORT,), pushes=(REF,), size=3)
    if m in ('invokevirtual','invokespecial','invokestatic'):
        tags={'invokevirtual':(3,), 'invokespecial':(4,6), 'invokestatic':(6,)}
        ref=resolve(tags[m]); sig=ref.signature
        pops=(() if m=='invokestatic' else (REF,))+sig.parameters
        pushes=() if sig.returns.kind=='void' else (sig.returns,)
        return emit(Op.CALL, sig.returns, (m,), pops=pops, pushes=pushes, ref=ref, size=3)
    name=m.removesuffix('_w')
    if name in ('goto',): return emit(Op.GOTO, targets=(one(),), size=3 if m.endswith('_w') else 2)
    match=re.fullmatch(r'if(?:_(s|a)cmp)?(eq|ne|lt|le|gt|ge)',name)
    if match:
        typ=REF if match[1]=='a' else SHORT
        if match[1]=='a' and match[2] not in ('eq','ne'): raise IRValidationError(m)
        return emit(Op.BRANCH, typ, (match[2], 'pair' if match[1] else 'zero'),
                    pops=(typ,typ) if match[1] else (typ,), targets=(one(),), size=3 if m.endswith('_w') else 2)
    if name in ('ifnull','ifnonnull'):
        return emit(Op.BRANCH, REF, ('eq' if name=='ifnull' else 'ne','null'),
                    pops=(REF,), targets=(one(),), size=3 if m.endswith('_w') else 2)
    if m in ('stableswitch','itableswitch','slookupswitch','ilookupswitch'):
        if not isinstance(operands,dict): raise IRValidationError('Switch operands must be a mapping')
        typ=TYPES[m[0]]
        if 'table' in m:
            low,high=operands['low'],operands['high']; jumps=operands['jumps']
            if high<low or len(jumps)!=high-low+1: raise IRValidationError('Invalid switch table')
            cases=tuple(zip(range(low,high+1),jumps))
            size=1+2+(4 if typ==SHORT else 8)+2*len(cases)
        else:
            cases=tuple(tuple(x) for x in operands['pairs'])
            if operands['npairs']!=len(cases): raise IRValidationError('Invalid switch pair count')
            keys=[x[0] for x in cases]
            if keys!=sorted(set(keys)): raise IRValidationError('Switch keys must be strictly increasing')
            size=5+(4 if typ==SHORT else 6)*len(cases)
        return emit(Op.SWITCH, typ, pops=(typ,), targets=(operands['default'],)+tuple(t for _,t in cases), cases=cases, size=size)
    if m in ('return','sreturn','ireturn','areturn'):
        typ=VOID if m=='return' else TYPES[m[0]]
        return emit(Op.RETURN, typ, pops=() if typ==VOID else (typ,))
    if m=='athrow': return emit(Op.THROW, REF, pops=(REF,))
    raise IRValidationError(f'Unsupported JCVM instruction {m} at {ins.offset}')
