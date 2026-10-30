"""D-07: the public CAPFile conversion preserves the typed pipeline contract."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cap_decompile.components.descriptor import MethodDescriptorInfo
from cap_decompile.components.header import CAPVersion
from cap_decompile.components.method_component import MethodComponent
from cap_decompile.model.cap_file import CAPFile
from jcvm_ir import Handler, INT, IRBuilder, IRValidationError, MethodInput, SHORT, Signature, Type, VOID, methods_from_cap
from main import build_cfgs, build_jcvm_ir, build_jvm_like_ir, build_soot_ir, load_cap, verify_methods
from soot_ir import SymbolTable


PROJECT = Path(__file__).resolve().parents[2]


def make_cap(*, body=b"\x7a", header=b"\x02\x00", token=9,
             access_flags=0x08, types=b"\x01\x10", handlers=()):
    """A real CAPFile with binary Method.cap and minimal unrelated components."""
    info = bytes([len(handlers)]) + b"".join(handlers) + header + body
    component = MethodComponent.parse_from_bytes(
        b"\x07" + len(info).to_bytes(2, "big") + info, CAPVersion.V22,
    )
    descriptor = SimpleNamespace(
        classes=[SimpleNamespace(this_class_ref=6, methods=[MethodDescriptorInfo(
            token=token, access_flags=access_flags, method_offset=1 + 8 * len(handlers),
            type_offset=2, bytecode_count=len(body), exception_handler_count=len(handlers),
            exception_handler_index=0,
        )])],
        types=SimpleNamespace(raw_types=types, constant_pool_count=0, constant_pool_types=[]),
    )
    cap = CAPFile(
        header=SimpleNamespace(package=SimpleNamespace(
            aid=bytes.fromhex("0102030405"), major_version=1, minor_version=2,
        )),
        directory=None, applet=None, import_componet=None,
        constant_pool=SimpleNamespace(constant_pool=[]), class_component=None,
        method_component=component, static_field=None, reference_location=None,
        descriptor=descriptor,
    )
    cap.link()
    return cap


class ModelConversionTests(unittest.TestCase):
    def test_static_method_preserves_identity_header_and_signature(self):
        cap = make_cap(header=b"\x02\x43", types=b"\x04\x54\x31")
        method, = cap.to_model()
        self.assertIsInstance(method, MethodInput)
        self.assertEqual((method.name, method.token, method.offset),
                         ("0102030405/class_6/method_1", 9, 1))
        self.assertEqual((method.max_stack, method.nargs, method.max_locals), (2, 4, 3))
        self.assertTrue(method.is_static)
        self.assertEqual(method.signature, Signature((INT, SHORT, Type("byte")), VOID))
        self.assertEqual(method.bytecodes, b"\x7a")
        self.assertEqual([(i.offset, i.mnemonic) for i in method.instructions], [(0, "return")])

    def test_instance_method_preserves_receiver_slot_and_parameter_signature(self):
        cap = make_cap(header=b"\x02\x24", access_flags=0, types=b"\x02\x41")
        method, = cap.to_model()
        self.assertFalse(method.is_static)
        self.assertEqual(method.nargs, 2)  # receiver + one short, not two parameters
        self.assertEqual(method.max_locals, 4)
        self.assertEqual(method.signature, Signature((SHORT,), VOID))

    def test_zero_values_and_empty_handler_table_remain_explicit(self):
        method, = make_cap(header=b"\x00\x00", token=0).to_model()
        self.assertEqual((method.token, method.max_stack, method.nargs, method.max_locals), (0, 0, 0, 0))
        self.assertEqual(method.exception_handlers, ())
        self.assertEqual(method.signature, Signature((), VOID))

    def test_handlers_keep_priority_catch_types_and_stop_bits_in_local_coordinates(self):
        # Two handlers: headers start at info offset 17; body starts at 19.
        handlers = (struct.pack(">HHHH", 19, 2, 21, 7),
                    struct.pack(">HHHH", 19, 0x8002, 21, 0))
        cap = make_cap(header=b"\x01\x00", body=b"\x01\x93\x3b\x7a", handlers=handlers)
        method, = cap.to_model()
        self.assertEqual(method.offset, 17)
        self.assertEqual(method.exception_handlers,
                         (Handler(0, 2, 2, 7, False), Handler(0, 2, 2, 0, True)))
        # The raw component retains its info-relative coordinates.
        self.assertEqual(cap.method_component.exception_handlers[0].start_offset, 19)

    def test_public_conversion_reaches_soot_with_a_binary_handler(self):
        cap = make_cap(header=b"\x01\x00", body=b"\x01\x93\x3b\x7a",
                       handlers=(struct.pack(">HHHH", 11, 0x8002, 13, 0),))
        methods = cap.to_model()
        cfgs = build_cfgs(methods)
        verify_methods(methods)
        ir = build_jcvm_ir(cap, methods, cfgs)
        self.assertEqual(ir[0].handlers, (Handler(0, 2, 2, 0, True),))
        self.assertEqual(ir[0].signature, Signature((), VOID))
        symbols = SymbolTable.from_dict({"package_aid": "0102030405", "package_version": [1, 2]})
        program = build_soot_ir(build_jvm_like_ir(ir), symbols)
        self.assertEqual(len(program.methods), 1)
        self.assertEqual([(t.priority, t.exception_type, t.stop_bit) for t in program.methods[0].traps],
                         [(0, "java.lang.Throwable", True)])

    def test_preserved_signature_enables_return_type_validation(self):
        cap = make_cap(header=b"\x01\x00", body=b"\x03\x78")  # sconst_0; sreturn in void()
        method, = cap.to_model()
        with self.assertRaisesRegex(IRValidationError, "Return type mismatch"):
            IRBuilder().build(method)

    def test_linked_methods_are_joined_by_offset_not_position_or_token(self):
        cap = make_cap()
        first = cap.descriptor.classes[0].methods[0]
        second = replace(first, method_offset=4)  # same token in another class
        cap.descriptor.classes.append(SimpleNamespace(this_class_ref=12, methods=[second]))
        cap.method_component.methods_data += b"\x00\x00\x7a"
        cap.link()
        cap.method_component.methods.reverse()
        methods = cap.to_model()
        self.assertEqual([m.offset for m in methods], [1, 4])
        self.assertEqual([m.token for m in methods], [9, 9])
        self.assertEqual([m.max_stack for m in methods], [2, 0])
        self.assertEqual([m.name for m in methods],
                         ["0102030405/class_6/method_1", "0102030405/class_12/method_4"])

    def test_real_caps_match_canonical_adapter_and_descriptor_metadata(self):
        fixtures = (("examples/name1/name1.cap", 7),
                    ("example_applet/scr/com/example/transactiontest/transaction_test.cap", 4))
        for fixture, count in fixtures:
            with self.subTest(fixture=fixture):
                cap = load_cap(PROJECT / fixture)
                methods = cap.to_model()
                self.assertEqual(methods, methods_from_cap(cap))
                self.assertEqual(len(methods), count)
                descriptors = [d for cls in cap.descriptor.classes for d in cls.methods]
                self.assertEqual([(m.token, m.offset, m.is_static) for m in methods],
                                 [(d.token, d.method_offset, bool(d.access_flags & 0x08)) for d in descriptors])

    def test_conversion_does_not_mutate_cap_or_share_mutable_results(self):
        cap = make_cap()
        before = deepcopy(cap)
        first = cap.to_model()
        second = cap.to_model()
        first[0].instructions.clear()
        first.clear()
        self.assertEqual(cap, before)
        self.assertEqual(len(second), 1)
        self.assertEqual(len(second[0].instructions), 1)

    def test_invalid_linked_offset_sets_are_rejected(self):
        for defect, message in (("missing", "not linked"), ("duplicate", "Duplicate method offsets"),
                                ("unmatched", "Unmatched linked methods")):
            with self.subTest(defect=defect):
                cap = make_cap()
                linked = cap.method_component.methods
                if defect == "missing":
                    linked.clear()
                elif defect == "duplicate":
                    linked.append(deepcopy(linked[0]))
                else:
                    linked.append(replace(linked[0], offset=100))
                with self.assertRaisesRegex(IRValidationError, message):
                    cap.to_model()

    def test_bytecode_length_mismatch_is_rejected(self):
        cap = make_cap()
        cap.descriptor.classes[0].methods[0].bytecode_count += 1
        with self.assertRaisesRegex(IRValidationError, "bytecode length differs"):
            cap.to_model()

    def test_missing_signature_and_inconsistent_nargs_are_rejected(self):
        for defect, message in (("signature", "Invalid type descriptor offset"),
                                ("nargs", "signature/header nargs mismatch")):
            with self.subTest(defect=defect):
                cap = make_cap()
                if defect == "signature":
                    cap.descriptor.classes[0].methods[0].type_offset = 999
                else:
                    cap.method_component.methods[0].header.nargs = 1
                with self.assertRaisesRegex(IRValidationError, message):
                    cap.to_model()

    def test_invalid_handler_slices_are_rejected(self):
        for index, count in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            with self.subTest(index=index, count=count):
                cap = make_cap()
                desc = cap.descriptor.classes[0].methods[0]
                desc.exception_handler_index, desc.exception_handler_count = index, count
                with self.assertRaisesRegex(IRValidationError, "Invalid method exception handler slice"):
                    cap.to_model()

    def test_unsupported_methods_are_rejected_before_decoding(self):
        cases = ((b"\x80\x10\x00\x20", 0x08), (b"\x40\x00", 0x08),
                 (b"\x10\x00", 0x08), (b"\x00\x00", 0x48))
        for header, flags in cases:
            with self.subTest(header=header, flags=flags):
                cap = make_cap(header=header, access_flags=flags)
                with patch("cap_decompile.model.method_info.parse_bytecode") as decode:
                    with self.assertRaisesRegex(IRValidationError, "ordinary concrete|Abstract methods"):
                        cap.to_model()
                    decode.assert_not_called()

    def test_empty_linked_model_returns_an_empty_list(self):
        cap = make_cap()
        cap.descriptor.classes.clear()
        cap.method_component.methods.clear()
        self.assertEqual(cap.to_model(), [])

    def test_importing_cap_parser_does_not_load_typed_or_runtime_stages(self):
        script = (
            "import sys\n"
            "from cap_decompile.model.cap_file import CAPFile\n"
            "assert not any(name.split('.')[0] in {'jcvm_ir', 'angr', 'pysoot', 'jpype'} "
            "for name in sys.modules)\n"
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=PROJECT,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
