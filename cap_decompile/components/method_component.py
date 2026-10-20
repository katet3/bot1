# components/method_component.py

from dataclasses import dataclass
from typing import List

from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion


# =========================
# Exception Handler
# =========================

@dataclass
class ExceptionHandlerInfo:
    start_offset: int
    stop_bit: int
    active_length: int
    handler_offset: int
    catch_type_index: int


# =========================
# Method Header
# =========================

@dataclass
class MethodHeaderInfo:
    flags: int
    max_stack: int
    nargs: int
    max_locals: int


@dataclass
class ExtendedMethodHeaderInfo:
    flags: int
    max_stack: int
    nargs: int
    max_locals: int


# =========================
# Final Method (готовый)
# =========================

@dataclass
class MethodInfo:
    offset: int
    header: MethodHeaderInfo | ExtendedMethodHeaderInfo
    bytecodes: bytes
    exception_handlers: List[ExceptionHandlerInfo]


# =========================
# Method Component
# =========================

@dataclass
class MethodComponent(CAPComponent):
    COMPONENT_TAG = 7

    handler_count: int
    exception_handlers: List[ExceptionHandlerInfo]

    # raw байты методов (всё после handlers)
    methods_data: bytes

    # результат после линковки
    methods: List[MethodInfo]

    # =========================
    # Parsing
    # =========================

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Method tag: {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()

        # =========================
        # Exception handlers
        # =========================
        handler_count = reader.read_u1()

        if not (0 <= handler_count <= 255):
            raise ValueError(f"Invalid handler_count: {handler_count}")

        exception_handlers = []

        for _ in range(handler_count):
            start_offset = reader.read_u2()

            bitfield = reader.read_u2()
            stop_bit = (bitfield >> 15) & 0x1
            active_length = bitfield & 0x7FFF

            handler_offset = reader.read_u2()
            catch_type_index = reader.read_u2()

            exception_handlers.append(
                ExceptionHandlerInfo(
                    start_offset=start_offset,
                    stop_bit=stop_bit,
                    active_length=active_length,
                    handler_offset=handler_offset,
                    catch_type_index=catch_type_index
                )
            )

        # =========================
        # Остальные байты = methods blob
        # =========================
        bytes_read = start_remaining - reader.remaining()
        remaining_size = size - bytes_read

        if remaining_size < 0:
            raise ValueError("Invalid Method component size")

        methods_data = reader.read_bytes(remaining_size)

        # =========================
        # Финальная проверка размера
        # =========================
        total_read = start_remaining - reader.remaining()
        if total_read != size:
            raise ValueError(
                f"Method component size mismatch: expected {size}, got {total_read}"
            )

        return cls(
            tag=tag,
            size=size,
            handler_count=handler_count,
            exception_handlers=exception_handlers,
            methods_data=methods_data,
            methods=[]
        )

    def link_with_descriptor(self, descriptor_component):
        """
        Разбирает methods_data последовательно, используя информацию
        из method_descriptor_info (bytecode_count).
        Порядок методов соответствует порядку class_descriptor_info и
        method_descriptor_info внутри них.
        """
        from .descriptor import DescriptorComponent  # на всякий случай

        reader = BinaryReader(self.methods_data)
        self.methods = []

        for cls_desc in descriptor_component.classes:
            for m_desc in cls_desc.methods:
                # Читаем method_header
                header = self._parse_method_header(reader)

                # Байткоды заданной длины
                bytecodes = reader.read_bytes(m_desc.bytecode_count)

                # Обработчики исключений
                start_idx = m_desc.exception_handler_index
                end_idx = start_idx + m_desc.exception_handler_count
                handlers = self.exception_handlers[start_idx:end_idx]

                self.methods.append(MethodInfo(
                    # offset можно сохранить как позицию начала метода в methods_data,
                    # но для дальнейшей работы он не обязателен.
                    offset=reader.tell() - len(bytecodes) - (2 if isinstance(header, MethodHeaderInfo) else ...),
                    header=header,
                    bytecodes=bytecodes,
                    exception_handlers=handlers
                ))

    # =========================
    # Header parsing
    # =========================

    @staticmethod
    def _parse_method_header(reader: BinaryReader):
        first = reader.read_u1()
        flags = (first >> 4) & 0xF

        is_extended = (flags & 0x8) != 0  # ACC_EXTENDED

        if is_extended:
            padding = first & 0xF
            if padding != 0:
                raise ValueError("Invalid padding in extended method header")

            max_stack = reader.read_u2()
            nargs = reader.read_u1()
            max_locals = reader.read_u2()

            return ExtendedMethodHeaderInfo(
                flags=flags,
                max_stack=max_stack,
                nargs=nargs,
                max_locals=max_locals
            )
        else:
            max_stack = first & 0xF

            second = reader.read_u1()
            nargs = (second >> 4) & 0xF
            max_locals = second & 0xF

            return MethodHeaderInfo(
                flags=flags,
                max_stack=max_stack,
                nargs=nargs,
                max_locals=max_locals
            )