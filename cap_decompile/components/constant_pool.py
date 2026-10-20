# components/constant_pool.py

from dataclasses import dataclass
from typing import List, Union
from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion

'''
struct ConstantPool.cap

constant_pool_component {
    u1 tag = 5
    u2 size
    u2 count
    cp_info constant_pool[count]
}

cp_info {
    u1 tag
    u1 info[3]
}
'''


CONSTANT_Classref = 1
CONSTANT_InstanceFieldref = 2
CONSTANT_VirtualMethodref = 3
CONSTANT_SuperMethodref = 4
CONSTANT_StaticFieldref = 5
CONSTANT_StaticMethodref = 6

@dataclass
class CPInfo:
    tag: int

@dataclass
class ConstantClassref(CPInfo):
    is_external: bool
    internal_offset: int = None
    package_token: int = None
    class_token: int = None

def parse_classref(info_bytes: bytes):
    b0, b1, b2 = info_bytes

    high_bit = (b0 & 0x80) >> 7

    if high_bit == 0:
        # internal_class_ref (u2)
        internal_offset = ((b0 << 8) | b1)
        return ConstantClassref(
            tag=CONSTANT_Classref,
            is_external=False,
            internal_offset=internal_offset
        )
    else:
        # external_class_ref
        package_token = b0 & 0x7F
        class_token = b1
        return ConstantClassref(
            tag=CONSTANT_Classref,
            is_external=True,
            package_token=package_token,
            class_token=class_token
        )
    
@dataclass
class ConstantFieldOrMethodRef(CPInfo):
    is_external_class: bool
    class_internal_offset: int = None
    package_token: int = None
    class_token: int = None
    token: int = None

def parse_field_or_method(tag: int, info_bytes: bytes):
    b0, b1, b2 = info_bytes

    high_bit = (b0 & 0x80) >> 7

    if high_bit == 0:
        class_internal_offset = ((b0 << 8) | b1)
        token = b2
        return ConstantFieldOrMethodRef(
            tag=tag,
            is_external_class=False,
            class_internal_offset=class_internal_offset,
            token=token
        )
    else:
        package_token = b0 & 0x7F
        class_token = b1
        token = b2
        return ConstantFieldOrMethodRef(
            tag=tag,
            is_external_class=True,
            package_token=package_token,
            class_token=class_token,
            token=token
        )
    
@dataclass
class ConstantStaticRef(CPInfo):
    is_external: bool
    internal_offset: int = None
    package_token: int = None
    class_token: int = None
    token: int = None

def parse_static_ref(tag: int, info_bytes: bytes):
    b0, b1, b2 = info_bytes

    high_bit = (b0 & 0x80) >> 7

    if high_bit == 0:
        # internal_ref
        offset = ((b1 << 8) | b2)
        return ConstantStaticRef(
            tag=tag,
            is_external=False,
            internal_offset=offset
        )
    else:
        package_token = b0 & 0x7F
        class_token = b1
        token = b2
        return ConstantStaticRef(
            tag=tag,
            is_external=True,
            package_token=package_token,
            class_token=class_token,
            token=token
        )
    
@dataclass
class ConstantPoolComponent(CAPComponent):
    COMPONENT_TAG = 5

    count: int
    constant_pool: List[CPInfo]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid ConstantPool tag: {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()
        if size <= 0:
            raise ValueError("ConstantPool size must be > 0")

        count = reader.read_u2()

        if cap_version in (CAPVersion.V22, CAPVersion.V21):
            constant_pool = []
            for _ in range(count):
                entry_tag = reader.read_u1()
                info = reader.read_bytes(3)

                if entry_tag == CONSTANT_Classref:
                    entry = parse_classref(info)

                elif entry_tag in (
                    CONSTANT_InstanceFieldref,
                    CONSTANT_VirtualMethodref,
                    CONSTANT_SuperMethodref,
                ):
                    entry = parse_field_or_method(entry_tag, info)

                elif entry_tag in (
                    CONSTANT_StaticFieldref,
                    CONSTANT_StaticMethodref,
                ):
                    entry = parse_static_ref(entry_tag, info)

                else:
                    raise ValueError(f"Unknown constant pool tag {entry_tag}")

                constant_pool.append(entry)
        else:
            raise ValueError("CAP not 2.2")

        bytes_read = start_remaining - reader.remaining()
        if bytes_read != size:
            raise ValueError(
                f"ConstantPool size mismatch: expected {size}, got {bytes_read}"
            )

        if reader.remaining() != 0:
            raise ValueError("ConstantPool parsing incomplete")

        return cls(
            tag=tag,
            size=size,
            count=count,
            constant_pool=constant_pool
        )
    
