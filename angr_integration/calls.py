"""Resolve loaded CAP calls and explicitly registered API models.

Virtual CAP overrides are selected by method token when available, not by the
synthetic per-offset names. Special calls retain the declared target.
"""
from dataclasses import dataclass

from .errors import HeapError


@dataclass(frozen=True)
class CallTarget:
    key: str | None
    model: object | None
    owner: str
    params: tuple[str, ...]
    returns: str
    static: bool


def invocation_mode(node):
    return {'SootStaticInvokeExpr': 'static', 'SootSpecialInvokeExpr': 'special',
            'SootVirtualInvokeExpr': 'virtual', 'SootInterfaceInvokeExpr': 'interface'}.get(type(node).__name__)


class CallResolver:
    def __init__(self, program, index, schema, api=None):
        self.program, self.index, self.schema, self.api = program, index, schema, api
        self.metadata = {m.key: m for c in program.metadata.classes for m in c.methods}
        self.externals = {(m.owner, m.name, m.params): m for m in program.external_methods}

    def resolve(self, node, actual_type=None):
        mode = invocation_mode(node)
        signature = node.class_name, node.method_name, tuple(node.method_params)
        if mode is None:
            raise HeapError('call_kind', f'Unsupported invocation {type(node).__name__}')
        static = mode == 'static'
        key = self.index.by_signature.get(signature)
        api_method = None
        if key is not None:
            if mode == 'interface':
                raise HeapError('interface_dispatch', 'Internal CAP interface dispatch requires an explicit interface-to-virtual token map')
            declared = self.program.methods[key]
            if ('STATIC' in declared.attrs) != static or declared.ret != node.type:
                raise HeapError('call_signature', f'Call disagrees with declaration: {signature}')
            token = self.metadata[key].token
            if mode in ('virtual', 'interface') and {'PRIVATE', 'CONSTRUCTOR'}.intersection(declared.attrs):
                raise HeapError('call_kind', f'Non-virtual method invoked virtually: {signature}')
        else:
            external = self.externals.get(signature)
            if external is not None and self.api is not None:
                api_method = self.api.lookup(external)
            if api_method is None:
                raise HeapError('external_call', f'Missing method/API model: {signature}')
            if api_method.static != static or api_method.returns != node.type:
                raise HeapError('call_signature', f'Call disagrees with API model: {signature}')
            token = api_method.token
        if len(node.args) != len(signature[2]):
            raise HeapError('call_signature', f'Argument count disagrees with {signature}')
        if not static:
            if actual_type is None:
                actual_type = node.class_name
            if not self.schema.assignable(actual_type, node.class_name):
                raise HeapError('call_receiver', f'{actual_type} is not a {node.class_name}')
            if mode == 'interface' and (api_method is None or
                    not self.api.accepts_receiver(api_method, actual_type, self.schema)):
                raise HeapError('interface_dispatch', 'Only explicitly modeled interface implementations are supported; CAP token maps are required for others')
            if mode in ('virtual', 'interface'):
                for cls in self.schema.lineage(actual_type):
                    for candidate in cls.methods:
                        if {'STATIC', 'PRIVATE', 'CONSTRUCTOR'}.intersection(candidate.attrs):
                            continue
                        matches = (candidate.token == token if token is not None
                                   else candidate.name == node.method_name)
                        if matches and candidate.params == signature[2] and candidate.returns == node.type:
                            if candidate.key not in self.program.methods:
                                raise HeapError('missing_body', f'No executable override: {candidate.key}')
                            key, api_method = candidate.key, None
                            break
                    else:
                        continue
                    break
            if api_method is not None and not self.api.accepts_receiver(api_method, actual_type, self.schema):
                raise HeapError('api_receiver', f'API model has no implementation for {actual_type}')
        owner = self.program.methods[key].class_name if key is not None else node.class_name
        return CallTarget(key, api_method, owner, signature[2], node.type, static)

    def potential_targets(self, node):
        if invocation_mode(node) == 'static':
            return (self.resolve(node),)
        # Check every declared concrete receiver; runtime checks its actual type.
        types = [c.name for c in self.schema.classes.values()
                 if not {'ABSTRACT', 'INTERFACE'}.intersection(c.attrs)
                 and self.schema.assignable(c.name, node.class_name)]
        if not types:
            return (self.resolve(node, node.class_name),)
        return tuple(self.resolve(node, ty) for ty in types)
