"""D-06: header sizes, blob-relative offsets and the typed adapter boundary."""
from copy import deepcopy
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from cap_decompile.components.binary_reader import BinaryReader
from cap_decompile.components.descriptor import MethodDescriptorInfo
from cap_decompile.components.header import CAPVersion
from cap_decompile.components.method_component import (
    ExtendedMethodHeaderInfo, MethodComponent, MethodHeaderInfo, MethodInfo,
)
from jcvm_ir import Handler, IRValidationError, methods_from_cap
from main import build_cfgs, build_jcvm_ir, build_jvm_like_ir, build_soot_ir, verify_methods
from soot_ir import SymbolTable


def component(blob, handlers=()):
    """Parse an actual Method.cap byte sequence, including its component header."""
    info = bytes([len(handlers)]) + b"".join(handlers) + blob
    payload = b"\x07" + len(info).to_bytes(2, "big") + info
    return MethodComponent.parse_from_bytes(payload, CAPVersion.V22)


def descriptor(counts, offsets=None, handler_slices=None):
    offsets = offsets if offsets is not None else [1] * len(counts)
    handler_slices = handler_slices if handler_slices is not None else [(0, 0)] * len(counts)
    methods = [MethodDescriptorInfo(
        token=index, access_flags=0x08, method_offset=offset, type_offset=2,
        bytecode_count=count, exception_handler_count=handler_count,
        exception_handler_index=handler_start,
    ) for index, (count, offset, (handler_start, handler_count)) in enumerate(
        zip(counts, offsets, handler_slices, strict=True)
    )]
    return SimpleNamespace(
        classes=[SimpleNamespace(this_class_ref=0, methods=methods)],
        types=SimpleNamespace(raw_types=b"\x01\x10", constant_pool_count=0, constant_pool_types=[]),
    )


def cap_for(method_component, method_descriptor):
    return SimpleNamespace(
        header=SimpleNamespace(package=SimpleNamespace(
            aid=bytes.fromhex("0102030405"), major_version=1, minor_version=0,
        )),
        constant_pool=SimpleNamespace(constant_pool=[]),
        method_component=method_component,
        descriptor=method_descriptor,
    )


class MethodHeaderTests(unittest.TestCase):
    def test_ordinary_header_consumes_two_bytes_and_preserves_nibbles(self):
        for raw, expected in ((b"\x00\x00", (0, 0, 0)), (b"\x0f\xff", (15, 15, 15)),
                              (b"\x03\x25", (3, 2, 5))):
            with self.subTest(raw=raw):
                reader = BinaryReader(b"\xaa\x55" + raw + b"\x7a")
                reader.seek(2)
                header = MethodComponent._parse_method_header(reader)
                self.assertIsInstance(header, MethodHeaderInfo)
                self.assertEqual((header.max_stack, header.nargs, header.max_locals), expected)
                self.assertEqual(reader.tell(), 4)
                self.assertEqual(reader.read_u1(), 0x7a)

    def test_extended_header_consumes_four_bytes_with_unsigned_u1_fields(self):
        for fields in ((16, 2, 32), (255, 255, 255), (0, 0, 0)):
            with self.subTest(fields=fields):
                reader = BinaryReader(b"\xaa\x55\x80" + bytes(fields) + b"\x7a\x03\x04")
                reader.seek(2)
                header = MethodComponent._parse_method_header(reader)
                self.assertIsInstance(header, ExtendedMethodHeaderInfo)
                self.assertEqual(header.flags, 0x8)
                self.assertEqual((header.max_stack, header.nargs, header.max_locals), fields)
                self.assertEqual(reader.tell(), 6)
                self.assertEqual(reader.read_bytes(3), b"\x7a\x03\x04")

    def test_header_parser_preserves_abstract_flag_without_claiming_execution_support(self):
        for raw in (b"\x40\x00", b"\xc0\x00\x00\x00"):
            with self.subTest(raw=raw):
                reader = BinaryReader(raw)
                header = MethodComponent._parse_method_header(reader)
                self.assertEqual(header.flags, raw[0] >> 4)
                self.assertEqual(reader.tell(), len(raw))

    def test_truncated_ordinary_header_reports_its_blob_offset(self):
        for raw in (b"", b"\x01"):
            with self.subTest(raw=raw):
                reader = BinaryReader(b"\xaa\x55" + raw)
                reader.seek(2)
                with self.assertRaisesRegex(ValueError, "Truncated.*method header.*offset 2"):
                    MethodComponent._parse_method_header(reader)

    def test_every_truncated_extended_header_reports_value_error(self):
        raw = b"\x80\x10\x02\x20"
        for length in (1, 2, 3):
            with self.subTest(length=length):
                reader = BinaryReader(b"\xaa\x55" + raw[:length])
                reader.seek(2)
                with self.assertRaisesRegex(ValueError, "Truncated extended method header.*offset 2"):
                    MethodComponent._parse_method_header(reader)

    def test_nonzero_extended_padding_is_rejected(self):
        for padding in range(1, 16):
            with self.subTest(padding=padding):
                reader = BinaryReader(bytes([0x80 | padding, 16, 0, 32]))
                with self.assertRaisesRegex(ValueError, "Invalid padding in extended method header"):
                    MethodComponent._parse_method_header(reader)

    def test_extended_method_links_without_swallowing_bytecodes_or_ellipsis_arithmetic(self):
        body = b"\x00\x00\x7a"
        parsed = component(b"\x80\x10\x00\x20" + body)
        parsed.link_with_descriptor(descriptor([len(body)]))
        self.assertEqual(len(parsed.methods), 1)
        linked = parsed.methods[0]
        self.assertEqual(linked.offset, 0)
        self.assertEqual(linked.header, ExtendedMethodHeaderInfo(8, 16, 0, 32))
        self.assertEqual(linked.bytecodes, body)

    def test_mixed_headers_have_exact_blob_offsets_across_classes(self):
        bodies = (b"\x00\x7a", b"\x00\x00\x7a", b"\x7a")
        blob = b"\x02\x00" + bodies[0] + b"\x80\x10\x00\x20" + bodies[1] + b"\x01\x00" + bodies[2]
        parsed = component(blob)
        desc = descriptor([2, 3, 1], offsets=[1, 5, 12])
        all_methods = desc.classes[0].methods
        desc.classes[0].methods = all_methods[:2]
        desc.classes.append(SimpleNamespace(this_class_ref=1, methods=all_methods[2:]))
        before = deepcopy(desc)
        parsed.link_with_descriptor(desc)
        self.assertEqual([m.offset for m in parsed.methods], [0, 4, 11])
        self.assertEqual([m.bytecodes for m in parsed.methods], list(bodies))
        self.assertEqual([type(m.header) for m in parsed.methods],
                         [MethodHeaderInfo, ExtendedMethodHeaderInfo, MethodHeaderInfo])
        self.assertEqual(parsed.methods_data, blob)
        self.assertEqual(desc, before)

    def test_handler_table_prefix_does_not_shift_blob_relative_offsets(self):
        # One 8-byte handler + count byte; extended header starts at info offset 9.
        raw_handler = struct.pack(">HHHH", 13, 0x8001, 15, 0)
        parsed = component(b"\x80\x10\x00\x20\x00\x7a\x7a", [raw_handler])
        parsed.link_with_descriptor(descriptor([3], offsets=[9], handler_slices=[(0, 1)]))
        linked = parsed.methods[0]
        self.assertEqual(linked.offset, 0)
        self.assertEqual(linked.bytecodes, b"\x00\x7a\x7a")
        self.assertEqual(linked.exception_handlers, parsed.exception_handlers)
        handler = linked.exception_handlers[0]
        self.assertEqual((handler.start_offset, handler.handler_offset, handler.active_length, handler.stop_bit),
                         (13, 15, 1, 1))

    def test_zero_length_bodies_do_not_change_header_offsets(self):
        parsed = component(b"\x40\x00\xc0\x00\x00\x00")
        parsed.link_with_descriptor(descriptor([0, 0], offsets=[1, 3]))
        self.assertEqual([m.offset for m in parsed.methods], [0, 2])
        self.assertEqual([m.bytecodes for m in parsed.methods], [b"", b""])

    def test_truncated_bytecode_body_is_rejected_for_both_header_forms(self):
        for header in (b"\x01\x00", b"\x80\x10\x00\x20"):
            with self.subTest(header=header):
                parsed = component(header + b"\x7a")
                with self.assertRaisesRegex(ValueError, "Truncated method bytecodes.*offset 0"):
                    parsed.link_with_descriptor(descriptor([2]))
                self.assertEqual(parsed.methods, [])

    def test_invalid_bytecode_count_is_not_used_as_a_slice_length(self):
        for count in (-1, True, 1.0, "1"):
            with self.subTest(count=count):
                parsed = component(b"\x01\x00\x7a")
                with self.assertRaisesRegex(ValueError, "Invalid bytecode_count.*offset 0"):
                    parsed.link_with_descriptor(descriptor([count]))

    def test_late_link_failure_preserves_previous_complete_method_list(self):
        for tail, count in ((b"\x80", 0), (b"\x80\x10\x00\x20\x7a", 2)):
            with self.subTest(tail=tail):
                parsed = component(b"\x01\x00\x7a" + tail)
                previous = [MethodInfo(99, MethodHeaderInfo(0, 0, 0, 0), b"\x7a", [])]
                parsed.methods = previous
                before = deepcopy(previous)
                with self.assertRaises(ValueError):
                    parsed.link_with_descriptor(descriptor([1, count], offsets=[1, 4]))
                self.assertIs(parsed.methods, previous)
                self.assertEqual(parsed.methods, before)

    def test_successful_relink_replaces_methods_without_appending_duplicates(self):
        parsed = component(b"\x80\x10\x00\x20\x7a")
        desc = descriptor([1])
        parsed.link_with_descriptor(desc)
        first = deepcopy(parsed.methods)
        parsed.link_with_descriptor(desc)
        self.assertEqual(parsed.methods, first)
        self.assertEqual(len(parsed.methods), 1)

    def test_typed_adapter_rejects_extended_header_before_decoding_bytecodes(self):
        parsed = component(b"\x80\x10\x00\x20\x7a")
        desc = descriptor([1])
        parsed.link_with_descriptor(desc)
        decode = Mock(side_effect=AssertionError("Unsupported method must not be decoded"))
        with self.assertRaisesRegex(IRValidationError, "Only ordinary concrete method headers"):
            methods_from_cap(cap_for(parsed, desc), decode=decode)
        decode.assert_not_called()

    def test_binary_ordinary_method_and_handlers_still_reach_soot(self):
        # Ordinary header @9, bytecodes @11: aconst_null; athrow; handler pop; return.
        raw_handler = struct.pack(">HHHH", 11, 0x8002, 13, 0)
        parsed = component(b"\x01\x00\x01\x93\x3b\x7a", [raw_handler])
        desc = descriptor([4], offsets=[9], handler_slices=[(0, 1)])
        parsed.link_with_descriptor(desc)
        cap = cap_for(parsed, desc)
        methods = methods_from_cap(cap)
        self.assertEqual(methods[0].offset, 9)
        self.assertEqual(methods[0].exception_handlers, (Handler(0, 2, 2, 0, True),))
        cfgs = build_cfgs(methods)
        verify_methods(methods)
        ir = build_jcvm_ir(cap, methods, cfgs)
        symbols = SymbolTable.from_dict({"package_aid": "0102030405", "package_version": [1, 0]})
        program = build_soot_ir(build_jvm_like_ir(ir), symbols)
        self.assertEqual(len(program.methods), 1)
        self.assertEqual(len(program.methods[0].traps), 1)
        self.assertEqual(program.methods[0].traps[0].stop_bit, True)


if __name__ == "__main__":
    unittest.main()
