"""Resolve CAP symbolic identities and Descriptor signatures, without API name guesses."""
from .model import Type, Signature, Reference, IRValidationError


class DescriptorTypes:
    def __init__(self, descriptor):
        self.data = descriptor.types.raw_types
        self.base = 2 + 2 * descriptor.types.constant_pool_count
        self.offsets = descriptor.types.constant_pool_types
        self.entries = {}
        pos = 0
        while pos < len(self.data):
            start = pos
            count = self.data[pos]
            pos += 1
            size = (count + 1) // 2
            raw = self.data[pos:pos+size]
            if not count or len(raw) != size:
                raise IRValidationError('Truncated or empty type descriptor')
            pos += size
            nibbles = [n for b in raw for n in (b >> 4, b & 15)]
            if count % 2 and nibbles[-1] != 0:
                raise IRValidationError('Nonzero descriptor padding')
            nibbles = nibbles[:count]
            types = []
            i = 0
            names = {1:'void', 2:'boolean', 3:'byte', 4:'short', 5:'int',
                     6:'reference', 10:'boolean[]', 11:'byte[]', 12:'short[]',
                     13:'int[]', 14:'reference[]'}
            while i < count:
                code = nibbles[i]; i += 1
                if code not in names:
                    raise IRValidationError(f'Unknown descriptor nibble {code}')
                ref = None
                if code in (6, 14):
                    if i+4 > count:
                        raise IRValidationError('Truncated class reference in descriptor')
                    ref = 0
                    for n in nibbles[i:i+4]: ref = (ref << 4) | n
                    i += 4
                types.append(Type(names[code], ref))
            self.entries[self.base+start] = tuple(types)

    def get(self, offset):
        if offset not in self.entries:
            raise IRValidationError(f'Invalid type descriptor offset {offset}')
        return self.entries[offset]

    def signature(self, offset):
        types = self.get(offset)
        if any(t.kind == 'void' for t in types[:-1]):
            raise IRValidationError('Void method parameter')
        return Signature(types[:-1], types[-1])


class ReferenceResolver:
    def __init__(self, cap_file):
        self.cap = cap_file
        self.types = DescriptorTypes(cap_file.descriptor)
        if len(self.types.offsets) != len(cap_file.constant_pool.constant_pool):
            raise IRValidationError('Descriptor/constant pool count mismatch')

    def resolve(self, index, expected_tags):
        pool = self.cap.constant_pool.constant_pool
        if not isinstance(index, int) or not 0 <= index < len(pool):
            raise IRValidationError(f'Invalid constant pool index {index}')
        entry = pool[index]
        if entry.tag not in expected_tags:
            raise IRValidationError(f'cp#{index}: expected tags {expected_tags}, got {entry.tag}')
        external = getattr(entry, 'is_external', getattr(entry, 'is_external_class', False))
        package = self.cap.header.package
        if external:
            token = entry.package_token
            packages = self.cap.import_componet.packages
            if token is None or not 0 <= token < len(packages):
                raise IRValidationError(f'Invalid package token {token}')
            package = packages[token]
        type_offset = self.types.offsets[index]
        signature = None
        field_type = None
        if entry.tag in (3, 4, 6):
            signature = self.types.signature(type_offset)
        elif entry.tag in (2, 5):
            types = self.types.get(type_offset)
            if len(types) != 1 or types[0].kind == 'void':
                raise IRValidationError('Invalid field descriptor')
            field_type = types[0]
        return Reference(index, entry.tag, package.aid.hex(),
                         (package.major_version, package.minor_version), external,
                         getattr(entry, 'class_token', None),
                         getattr(entry, 'class_internal_offset',
                                 getattr(entry, 'internal_offset', None) if entry.tag == 1 else None),
                         getattr(entry, 'token', None),
                         getattr(entry, 'internal_offset', None) if entry.tag in (5, 6) else None,
                         signature, field_type)
