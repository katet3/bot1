"""D-08: complete reads, stable cursors on failure and component truncation."""
from pathlib import Path
import unittest

from cap_decompile.components.binary_reader import BinaryReader
from cap_decompile.components.applet import AppletComponent
from cap_decompile.components.class_component import ClassComponent, parse_type_descriptor
from cap_decompile.components.constant_pool import ConstantPoolComponent
from cap_decompile.components.descriptor import DescriptorComponent
from cap_decompile.components.directory import DirectoryComponent
from cap_decompile.components.header import HeaderComponent, CAPVersion
from cap_decompile.components.import_component import ImportComponent
from cap_decompile.components.method_component import MethodComponent
from cap_decompile.components.reference_location import ReferenceLocationComponent
from cap_decompile.components.static_field import StaticFieldComponent
from cap_decompile.container.cap_container import CAPContainer


class BinaryReaderTests(unittest.TestCase):
    def test_primitives_are_big_endian_and_bytes_are_exact(self):
        reader = BinaryReader(bytes.fromhex("ff 8001 80000001 61 62"))
        self.assertEqual(reader.read_u1(), 255)
        self.assertEqual(reader.read_u2(), 32769)
        self.assertEqual(reader.read_u4(), 2147483649)
        self.assertEqual(reader.read_bytes(2), b"ab")
        self.assertEqual((reader.tell(), reader.remaining()), (9, 0))

    def test_zero_length_read_is_valid_at_eof(self):
        for data in (b"", b"ab"):
            with self.subTest(data=data):
                reader = BinaryReader(data)
                reader.seek(len(data))
                self.assertEqual(reader.read_bytes(0), b"")
                self.assertEqual(reader.tell(), len(data))

    def test_short_read_reports_range_and_does_not_advance(self):
        reader = BinaryReader(b"abc")
        reader.seek(1)
        with self.assertRaises(ValueError) as caught:
            reader.read_bytes(3)
        error = caught.exception
        self.assertEqual(type(error).__name__, "BinaryParseError")
        self.assertEqual((error.offset, error.needed, error.available), (1, 3, 2))
        self.assertEqual(error.context, "read_bytes")
        self.assertIn("offset 1", str(error))
        self.assertEqual((reader.tell(), reader.remaining()), (1, 2))
        self.assertEqual(reader.read_bytes(2), b"bc")

    def test_invalid_read_lengths_never_change_the_cursor(self):
        for length in (-1, -100, True, False, 1.0, "1", None):
            with self.subTest(length=length):
                reader = BinaryReader(b"abcd")
                reader.seek(2)
                with self.assertRaises(ValueError):
                    reader.read_bytes(length)
                self.assertEqual(reader.tell(), 2)

    def test_every_truncated_primitive_fails_before_advancing(self):
        for name, width in (("read_u1", 1), ("read_u2", 2), ("read_u4", 4)):
            for available in range(width):
                with self.subTest(name=name, available=available):
                    reader = BinaryReader(b"ab" + b"\x00" * available)
                    reader.seek(2)
                    with self.assertRaises(ValueError) as caught:
                        getattr(reader, name)()
                    error = caught.exception
                    self.assertEqual((error.offset, error.needed, error.available), (2, width, available))
                    self.assertEqual(error.context, name)
                    self.assertEqual(reader.tell(), 2)

    def test_seek_accepts_both_endpoints_and_explicit_rewind(self):
        reader = BinaryReader(b"ab")
        reader.seek(2)
        self.assertEqual(reader.remaining(), 0)
        reader.seek(0)
        self.assertEqual(reader.read_u1(), ord("a"))

    def test_invalid_seek_is_rejected_without_mutation(self):
        for offset in (-1, 3, True, False, 1.0, "1", None):
            with self.subTest(offset=offset):
                reader = BinaryReader(b"ab")
                reader.seek(1)
                with self.assertRaises(ValueError):
                    reader.seek(offset)
                self.assertEqual(reader.tell(), 1)

    def test_skip_is_a_bounded_forward_operation(self):
        reader = BinaryReader(b"abcd")
        reader.skip(2)
        for length in (-1, 3, True, False, 1.0, "1", None):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    reader.skip(length)
                self.assertEqual(reader.tell(), 2)
        reader.skip(0)
        reader.skip(2)
        self.assertEqual((reader.tell(), reader.remaining()), (4, 0))

    def test_corrupted_public_cursor_cannot_trigger_python_negative_indexing(self):
        for offset in (-1, 5, True, 1.5):
            for name in ("read_u1", "read_u2", "read_u4", "read_bytes", "skip"):
                with self.subTest(offset=offset, name=name):
                    reader = BinaryReader(b"abcd")
                    reader.offset = offset
                    with self.assertRaises(ValueError):
                        if name in ("read_bytes", "skip"):
                            getattr(reader, name)(1)
                        else:
                            getattr(reader, name)()
                    self.assertEqual(reader.offset, offset)


class ComponentReadBoundaryTests(unittest.TestCase):
    def test_method_component_cannot_accept_a_virtual_declared_size(self):
        # Count byte + declared 5-byte blob; only 2 blob bytes actually exist.
        with self.assertRaisesRegex(ValueError, "read_bytes.*offset 4"):
            MethodComponent.parse_from_bytes(b"\x07\x00\x06\x00\x01\x00", CAPVersion.V22)

    def test_class_type_descriptor_cannot_return_a_short_nibble_payload(self):
        reader = BinaryReader(b"\x05\x12")  # five nibbles require three payload bytes
        with self.assertRaises(ValueError) as caught:
            parse_type_descriptor(reader)
        self.assertEqual((caught.exception.offset, caught.exception.needed, caught.exception.available), (1, 3, 1))
        self.assertEqual(reader.tell(), 1)  # count was read, failed payload read was not

    def test_every_truncated_prefix_of_real_components_is_rejected_as_value_error(self):
        root = Path(__file__).resolve().parents[2]
        container = CAPContainer(root / "examples/name1/name1.cap")
        container.load()
        header_data = container.get_component("Header.cap")
        version = HeaderComponent.parse_from_bytes(header_data).cap_version
        parsers = {
            "Header.cap": lambda data: HeaderComponent.parse_from_bytes(data),
            "Directory.cap": lambda data: DirectoryComponent.parse_from_bytes(data, version),
            "Applet.cap": lambda data: AppletComponent.parse_from_bytes(data, version),
            "Import.cap": lambda data: ImportComponent.parse_from_bytes(data, version),
            "ConstantPool.cap": lambda data: ConstantPoolComponent.parse_from_bytes(data, version),
            "Class.cap": lambda data: ClassComponent.parse_from_bytes(data, version),
            "Method.cap": lambda data: MethodComponent.parse_from_bytes(data, version),
            "StaticField.cap": lambda data: StaticFieldComponent.parse_from_bytes(data, version),
            "RefLocation.cap": lambda data: ReferenceLocationComponent.parse_from_bytes(data, version),
            "Descriptor.cap": lambda data: DescriptorComponent.parse_from_bytes(data, version),
        }
        for name, parse in parsers.items():
            data = container.get_component(name)
            parse(data)
            for end in range(len(data)):
                with self.subTest(component=name, length=end):
                    with self.assertRaises(ValueError):
                        parse(data[:end])


if __name__ == "__main__":
    unittest.main()
