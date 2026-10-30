"""Adapter for the project's CAPFile. No binary CAP parsing is performed here."""
from dataclasses import dataclass
from .model import Handler, Signature, IRValidationError
from .resolver import ReferenceResolver


@dataclass
class MethodInput:
    """Canonical decoded input with method metadata and method-local handlers."""

    name: str
    token: int
    offset: int  # Method component info-relative header offset
    bytecodes: bytes
    instructions: list
    max_stack: int
    nargs: int
    max_locals: int
    exception_handlers: tuple[Handler, ...]
    signature: Signature
    is_static: bool


def methods_from_cap(cap_file, decode=None):
    """Join linked methods with Descriptor metadata for the typed pipeline.

    CAPFile.to_model delegates here; both entry points return MethodInput objects.
    Supports the supplied linker's blob-relative MethodInfo.offset convention.
    The typed pipeline accepts only ordinary concrete headers. Structural decoding
    of extended headers by the CAP linker does not enable their lowering here.
    """
    if decode is None:
        from cap_decompile.model.method_info import parse_bytecode
        decode = parse_bytecode
    resolver = ReferenceResolver(cap_file)
    component = cap_file.method_component
    blob_base = 1 + 8 * component.handler_count
    by_offset = {m.offset + blob_base: m for m in component.methods}
    if len(by_offset)!=len(component.methods):
        raise IRValidationError('Duplicate method offsets')
    result=[]; seen=set()
    for cls in cap_file.descriptor.classes:
        for desc in cls.methods:
            if desc.access_flags & 0x40:
                raise IRValidationError('Abstract methods require upstream linker support')
            if desc.method_offset not in by_offset:
                raise IRValidationError(f'Method offset {desc.method_offset} not linked; fix CAP linker')
            m=by_offset[desc.method_offset]; seen.add(desc.method_offset)
            if m.header.flags:
                raise IRValidationError('Only ordinary concrete method headers are supported by this adapter')
            if len(m.bytecodes)!=desc.bytecode_count:
                raise IRValidationError('Method bytecode length differs from Descriptor')
            sig=resolver.types.signature(desc.type_offset)
            static=bool(desc.access_flags & 0x08)
            nargs=sum(t.slots for t in sig.parameters)+(0 if static else 1)
            if nargs!=m.header.nargs:
                raise IRValidationError(f'Method {desc.method_offset}: signature/header nargs mismatch')
            start=desc.exception_handler_index
            stop=start+desc.exception_handler_count
            if not 0<=start<=stop<=len(component.exception_handlers):
                raise IRValidationError('Invalid method exception handler slice')
            bytecode_base=desc.method_offset+2
            handlers=tuple(Handler(h.start_offset-bytecode_base,
                                   h.start_offset+h.active_length-bytecode_base,
                                   h.handler_offset-bytecode_base,
                                   h.catch_type_index,bool(h.stop_bit))
                           for h in component.exception_handlers[start:stop])
            name=f'{cap_file.header.package.aid.hex()}/class_{cls.this_class_ref}/method_{desc.method_offset}'
            result.append(MethodInput(name,desc.token,desc.method_offset,m.bytecodes,
                                      decode(m.bytecodes),m.header.max_stack,m.header.nargs,
                                      m.header.max_locals,handlers,sig,static))
    if seen!=set(by_offset): raise IRValidationError('Unmatched linked methods')
    return result
