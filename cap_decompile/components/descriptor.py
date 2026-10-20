from dataclasses import dataclass
from typing import List, Union

from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion


# =========================
# Field Descriptor
# =========================

@dataclass
class FieldRef:
    class_ref: int
    token: int


@dataclass
class FieldDescriptorInfo:
    token: int
    access_flags: int
    is_static: bool
    field_ref: FieldRef
    is_primitive: bool
    type_value: int


# =========================
# Method Descriptor
# =========================

@dataclass
class MethodDescriptorInfo:
    token: int
    access_flags: int
    method_offset: int
    type_offset: int
    bytecode_count: int
    exception_handler_count: int
    exception_handler_index: int


# =========================
# Class Descriptor
# =========================

@dataclass
class ClassDescriptorInfo:
    token: int
    access_flags: int
    this_class_ref: int
    interface_count: int
    field_count: int
    method_count: int
    interfaces: List[int]
    fields: List[FieldDescriptorInfo]
    methods: List[MethodDescriptorInfo]


# =========================
# Type Descriptor Info
# =========================

@dataclass
class TypeDescriptorInfo:
    constant_pool_count: int
    constant_pool_types: List[int]
    raw_types: bytes  # оставляем как raw (парсится отдельно при необходимости)


# =========================
# Descriptor Component
# =========================

@dataclass
class DescriptorComponent(CAPComponent):
    COMPONENT_TAG = 11

    class_count: int
    classes: List[ClassDescriptorInfo]
    types: TypeDescriptorInfo

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Descriptor tag: {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()

        # =========================
        # Classes
        # =========================
        class_count = reader.read_u1()

        classes = []
        for _ in range(class_count):
            classes.append(cls._parse_class_descriptor(reader))

        # =========================
        # Types
        # =========================
        types = cls._parse_type_descriptor(reader)

        # =========================
        # Size validation
        # =========================
        bytes_read = start_remaining - reader.remaining()
        if bytes_read != size:
            raise ValueError(
                f"Descriptor size mismatch: expected {size}, got {bytes_read}"
            )

        if reader.remaining() != 0:
            raise ValueError("Descriptor parsing incomplete")

        return cls(
            tag=tag,
            size=size,
            class_count=class_count,
            classes=classes,
            types=types
        )

    # =========================
    # Helpers
    # =========================

    @staticmethod
    def _parse_class_descriptor(reader: BinaryReader) -> ClassDescriptorInfo:
        token = reader.read_u1()
        access_flags = reader.read_u1()
        this_class_ref = reader.read_u2()

        interface_count = reader.read_u1()
        field_count = reader.read_u2()
        method_count = reader.read_u2()

        interfaces = [reader.read_u2() for _ in range(interface_count)]

        fields = [
            DescriptorComponent._parse_field_descriptor(reader)
            for _ in range(field_count)
        ]

        methods = [
            DescriptorComponent._parse_method_descriptor(reader)
            for _ in range(method_count)
        ]

        return ClassDescriptorInfo(
            token=token,
            access_flags=access_flags,
            this_class_ref=this_class_ref,
            interface_count=interface_count,
            field_count=field_count,
            method_count=method_count,
            interfaces=interfaces,
            fields=fields,
            methods=methods
        )

    @staticmethod
    def _parse_field_descriptor(reader: BinaryReader) -> FieldDescriptorInfo:
        token = reader.read_u1()
        access_flags = reader.read_u1()

        is_static = (access_flags & 0x08) != 0  # ACC_STATIC

        # field_ref ВСЕГДА занимает 3 байта: class_ref (2) + token (1)
        class_ref = reader.read_u2()
        token_field = reader.read_u1()

        # В спецификации 3.0.5 оба варианта структурно одинаковы
        field_ref = FieldRef(class_ref=class_ref, token=token_field)

        type_value = reader.read_u2()
        is_primitive = (type_value & 0x8000) != 0

        return FieldDescriptorInfo(
            token=token,
            access_flags=access_flags,
            is_static=is_static,
            field_ref=field_ref,
            is_primitive=is_primitive,
            type_value=type_value
        )

    @staticmethod
    def _parse_method_descriptor(reader: BinaryReader) -> MethodDescriptorInfo:
        token = reader.read_u1()
        access_flags = reader.read_u1()
        method_offset = reader.read_u2()
        type_offset = reader.read_u2()
        bytecode_count = reader.read_u2()
        exception_handler_count = reader.read_u2()
        exception_handler_index = reader.read_u2()

        return MethodDescriptorInfo(
            token=token,
            access_flags=access_flags,
            method_offset=method_offset,
            type_offset=type_offset,
            bytecode_count=bytecode_count,
            exception_handler_count=exception_handler_count,
            exception_handler_index=exception_handler_index
        )

    @staticmethod
    def _parse_type_descriptor(reader: BinaryReader) -> TypeDescriptorInfo:
        constant_pool_count = reader.read_u2()

        constant_pool_types = [
            reader.read_u2()
            for _ in range(constant_pool_count)
        ]

        # всё остальное — это type_desc[]
        raw_types = reader.read_bytes(reader.remaining())

        return TypeDescriptorInfo(
            constant_pool_count=constant_pool_count,
            constant_pool_types=constant_pool_types,
            raw_types=raw_types
        )