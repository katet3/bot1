# components/class_component.py

from dataclasses import dataclass
from typing import List, Union
from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion

'''
struct Class.cap

u1 tag = 6
u2 size
u2 signature_pool_length
type_descriptor signature_pool[]
interface_info interfaces[]
class_info classes[]
'''


@dataclass
class ClassRef:
    is_external: bool
    internal_offset: int = None
    package_token: int = None
    class_token: int = None


def parse_class_ref(reader: BinaryReader) -> ClassRef:
    b0 = reader.read_u1()
    b1 = reader.read_u1()

    if b0 == 0xFF and b1 == 0xFF:
        return ClassRef(is_external=False, internal_offset=0xFFFF)

    high_bit = (b0 & 0x80) >> 7

    if high_bit == 0:
        internal_offset = ((b0 << 8) | b1)
        return ClassRef(False, internal_offset=internal_offset)
    else:
        package_token = b0 & 0x7F
        class_token = b1
        return ClassRef(True,
                        package_token=package_token,
                        class_token=class_token)
    

@dataclass
class TypeDescriptor:
    nibble_count: int
    raw_bytes: bytes

def parse_type_descriptor(reader: BinaryReader) -> TypeDescriptor:
    nibble_count = reader.read_u1()
    byte_length = (nibble_count + 1) // 2
    data = reader.read_bytes(byte_length)

    return TypeDescriptor(nibble_count, data)
    

@dataclass
class InterfaceInfo:
    flags: int
    interface_count: int
    superinterfaces: List[ClassRef]
    interface_name: bytes | None
    offset: int | None = None  # Class.cap info-relative offset (after tag/size).

def parse_interface_info(reader: BinaryReader):
    bitfield = reader.read_u1()

    flags = (bitfield >> 4) & 0xF
    interface_count = bitfield & 0xF

    superinterfaces = [
        parse_class_ref(reader)
        for _ in range(interface_count)
    ]

    is_remote = (flags & 0x2) != 0

    if is_remote:
        length = reader.read_u1()
        name = reader.read_bytes(length)
    else:
        name = None

    return InterfaceInfo(flags, interface_count,
                        superinterfaces, name)
    


@dataclass
class ImplementedInterfaceInfo:
    interface: ClassRef
    count: int
    index: List[int]

def parse_implemented_interface(reader: BinaryReader):
    interface = parse_class_ref(reader)
    count = reader.read_u1()
    index = [reader.read_u1() for _ in range(count)]
    return ImplementedInterfaceInfo(interface, count, index)
    

@dataclass
class RemoteMethodInfo:
    remote_method_hash: int
    signature_offset: int
    virtual_method_token: int


@dataclass
class RemoteInterfaceInfo:
    remote_methods: List[RemoteMethodInfo]
    hash_modifier: bytes
    class_name: bytes
    remote_interfaces: List[ClassRef]

def parse_remote_interface_info(reader: BinaryReader, is_remote: bool):
    if not is_remote:
        return None

    remote_methods_count = reader.read_u1()

    remote_methods = []
    for _ in range(remote_methods_count):
        h = reader.read_u2()
        sig_offset = reader.read_u2()
        vtoken = reader.read_u1()
        remote_methods.append(
            RemoteMethodInfo(h, sig_offset, vtoken)
        )

    hash_modifier_length = reader.read_u1()
    hash_modifier = reader.read_bytes(hash_modifier_length)

    class_name_length = reader.read_u1()
    class_name = reader.read_bytes(class_name_length)

    remote_interfaces_count = reader.read_u1()
    remote_interfaces = [
        parse_class_ref(reader)
        for _ in range(remote_interfaces_count)
    ]

    return RemoteInterfaceInfo(
        remote_methods,
        hash_modifier,
        class_name,
        remote_interfaces
    )
    

@dataclass
class ClassInfo:
    flags: int
    interface_count: int
    super_class_ref: ClassRef
    declared_instance_size: int
    first_reference_token: int
    reference_count: int
    public_method_table_base: int
    public_method_table_count: int
    package_method_table_base: int
    package_method_table_count: int
    public_virtual_method_table: List[int]
    package_virtual_method_table: List[int]
    interfaces: List[ImplementedInterfaceInfo]
    remote_info: RemoteInterfaceInfo | None
    offset: int | None = None  # Join Class.cap declarations with Descriptor.cap.

def parse_class_info(reader: BinaryReader):
    bitfield = reader.read_u1()

    flags = (bitfield >> 4) & 0xF
    interface_count = bitfield & 0xF

    super_class_ref = parse_class_ref(reader)

    declared_instance_size = reader.read_u1()
    first_reference_token = reader.read_u1()
    reference_count = reader.read_u1()

    public_base = reader.read_u1()
    public_count = reader.read_u1()

    package_base = reader.read_u1()
    package_count = reader.read_u1()

    public_table = [reader.read_u2()
                    for _ in range(public_count)]

    package_table = [reader.read_u2()
                    for _ in range(package_count)]

    interfaces = [
        parse_implemented_interface(reader)
        for _ in range(interface_count)
    ]

    is_remote = (flags & 0x2) != 0
    remote_info = parse_remote_interface_info(reader, is_remote)

    return ClassInfo(
        flags,
        interface_count,
        super_class_ref,
        declared_instance_size,
        first_reference_token,
        reference_count,
        public_base,
        public_count,
        package_base,
        package_count,
        public_table,
        package_table,
        interfaces,
        remote_info
    )


@dataclass
class ClassComponent(CAPComponent):
    COMPONENT_TAG = 6

    signature_pool: List[TypeDescriptor]
    interfaces: List[InterfaceInfo]
    classes: List[ClassInfo]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        if len(data) < 3:
            raise ValueError("Truncated Class component")
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Class component tag {tag}")

        size = reader.read_u2()
        if size != len(data) - 3:
            raise ValueError("Class component size mismatch")
        component_end = reader.offset + size

        signature_pool = []
        if cap_version != CAPVersion.V21:
            if reader.remaining() < 2:
                raise ValueError("Missing signature_pool_length in CAP 2.2+ Class")
            signature_pool_length = reader.read_u2()
            sig_end = reader.offset + signature_pool_length
            if sig_end > component_end:
                raise ValueError("Truncated Class signature pool")

            while reader.offset < sig_end:
                signature_pool.append(parse_type_descriptor(reader))

            if reader.offset != sig_end:
                raise ValueError("Signature pool size mismatch")

        interfaces = []
        classes = []

        while reader.offset < component_end:

            pos = reader.offset
            bitfield = reader.read_u1()
            reader.offset = pos

            flags = (bitfield >> 4) & 0xF
            is_interface = (flags & 0x8) != 0

            if is_interface:
                interface = parse_interface_info(reader)
                interface.offset = pos - 3
                interfaces.append(interface)
            else:
                class_info = parse_class_info(reader)
                class_info.offset = pos - 3
                classes.append(class_info)

        if reader.offset != component_end:
            raise ValueError("Class component size mismatch")

        return cls(tag, size, signature_pool, interfaces, classes)
