"""D-08: binary operand layouts, switch bounds and the decoder/IR contract."""
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cap_decompile.model import method_info as decoder
from cfg_generator.builder import build_cfg
from jcvm_ir import INT, IRBuilder, IRValidationError, MethodInput, Op, Signature, Type, VOID
from jcvm_ir.lowering import lower
from jvm_like_ir import JVMLikeIRBuilder
from soot_ir import SootIRBuilder, SymbolTable
from verification_engine.verifier import Verifier


SWITCHES = {"stableswitch": 0x73, "itableswitch": 0x74,
            "slookupswitch": 0x75, "ilookupswitch": 0x76}


def switch_bytes(name, *, default=0, keys=(-1, 0), targets=(0, 0)):
    """Encode independent spec fixtures, not using the decoder's width table."""
    data = bytes([SWITCHES[name]]) + struct.pack(">h", default)
    width = ">h" if name.startswith("s") else ">i"
    if "table" in name:
        data += struct.pack(width, keys[0]) + struct.pack(width, keys[-1])
        data += b"".join(struct.pack(">h", target) for target in targets)
    else:
        data += struct.pack(">H", len(keys))
        data += b"".join(struct.pack(width, key) + struct.pack(">h", target)
                         for key, target in zip(keys, targets, strict=True))
    return data


def method(body, *, returns=VOID, locals_=0):
    return MethodInput("0102030405/class_0/method_0", 0, 0, body, decoder.parse_bytecode(body),
                       2, 0, locals_, (), Signature((), returns), True)


class FixedOperandTests(unittest.TestCase):
    def test_signed_int_push_is_one_operand_with_full_range(self):
        for value in (-(1 << 31), -1, 0, (1 << 31) - 1):
            with self.subTest(value=value):
                first, tail = decoder.parse_bytecode(b"\x14" + struct.pack(">i", value) + b"\x00")
                self.assertEqual((first.mnemonic, first.operands, tail.offset), ("iipush", [value], 5))

    def test_static_field_indices_are_unsigned_u2_operands(self):
        for opcode in range(0x7b, 0x83):
            with self.subTest(opcode=opcode):
                first, tail = decoder.parse_bytecode(bytes([opcode, 0x80, 0xff, 0]))
                self.assertEqual(first.operands, [33023])
                self.assertEqual(tail.offset, 3)
                typ = {"a": "reference", "b": "byte", "s": "short", "i": "int"}[first.mnemonic[-1]]
                resolver = Mock()
                resolver.resolve.return_value = SimpleNamespace(field_type=Type(typ))
                _, size = lower(first, resolver)
                resolver.resolve.assert_called_once_with(33023, (5,))
                self.assertEqual(size, 3)

    def test_all_local_indices_are_unsigned_bytes(self):
        for opcode in (0x15, 0x16, 0x17, 0x28, 0x29, 0x2a, 0x72):
            with self.subTest(opcode=opcode):
                first, tail = decoder.parse_bytecode(bytes([opcode, 255, 0]))
                self.assertEqual((first.operands, tail.offset), ([255], 2))

    def test_short_increments_use_signed_byte_constants(self):
        for opcode in (0x59, 0x5a):
            for value in (-128, -1, 0, 127):
                with self.subTest(opcode=opcode, value=value):
                    first, tail = decoder.parse_bytecode(bytes([opcode, 255]) + struct.pack(">b", value) + b"\x00")
                    self.assertEqual((first.operands, tail.offset), ([255, value], 3))
                    operation, size = lower(first, None)
                    self.assertEqual((operation.op, operation.args, size), (Op.INCREMENT, (255, value), 3))

    def test_wide_increments_have_a_byte_index_and_signed_short_constant(self):
        for opcode in (0x96, 0x97):
            self.assertEqual(decoder.OPCODES[opcode][1], 3)
            for value in (-32768, -1, 0, 32767):
                with self.subTest(opcode=opcode, value=value):
                    first, tail = decoder.parse_bytecode(bytes([opcode, 255]) + struct.pack(">h", value) + b"\x00")
                    self.assertEqual((first.operands, tail.offset), ([255, value], 4))
                    with self.assertRaisesRegex(IRValidationError, "Unsupported JCVM instruction"):
                        lower(first, None)

    def test_dup_x_and_swap_x_consume_the_mn_byte(self):
        for opcode in (0x3f, 0x40):
            with self.subTest(opcode=opcode):
                self.assertEqual(decoder.OPCODES[opcode][1], 1)
                first, tail = decoder.parse_bytecode(bytes([opcode, 0x21, 0]))
                self.assertEqual((first.operands, tail.offset), ([0x21], 2))
                with self.assertRaisesRegex(IRValidationError, "Unsupported JCVM instruction"):
                    lower(first, None)

    def test_composite_reference_operands_keep_their_boundaries(self):
        for raw, expected in ((b"\x94\x0e\x80\xff", [14, 33023]),
                              (b"\x95\x00\x80\xff", [0, 33023]),
                              (b"\x8e\x03\x80\xff\xfe", [3, 33023, 254])):
            with self.subTest(raw=raw):
                first, tail = decoder.parse_bytecode(raw + b"\x00")
                self.assertEqual((first.operands, tail.offset), (expected, len(raw)))

    def test_every_fixed_opcode_has_a_complete_explicit_decode(self):
        for opcode, (name, width) in decoder.OPCODES.items():
            if width < 0:
                continue
            with self.subTest(name=name):
                raw = bytes([opcode]) + b"\x01" * width
                first, tail = decoder.parse_bytecode(raw + b"\x00")
                self.assertEqual((first.mnemonic, tail.mnemonic, tail.offset), (name, "nop", len(raw)))
                for end in range(1, len(raw)):
                    with self.subTest(length=end):
                        with self.assertRaises(ValueError) as caught:
                            decoder.parse_bytecode(b"\x00" + raw[:end])
                        self.assertEqual(caught.exception.offset, 1)
                        self.assertIn(name, caught.exception.context)

    def test_an_unknown_operand_format_is_rejected_instead_of_returning_raw_bytes(self):
        with patch.dict(decoder.OPCODES, {0xba: ("future_operand", 2)}):
            with self.assertRaisesRegex(ValueError, "Unsupported operand format"):
                decoder.parse_bytecode(b"\xba\x12\x34")

    def test_unknown_opcodes_report_the_instruction_offset(self):
        for opcode in sorted(set(range(256)) - decoder.OPCODES.keys()):
            with self.subTest(opcode=opcode):
                with self.assertRaises(ValueError) as caught:
                    decoder.parse_bytecode(bytes([0, opcode]))
                self.assertIn("Unknown opcode", str(caught.exception))
                self.assertEqual(caught.exception.offset, 1)

    def test_numeric_helpers_reject_out_of_range_and_noninteger_offsets(self):
        for name, width in (("read_u1", 1), ("read_s1", 1), ("read_u2", 2),
                            ("read_s2", 2), ("read_u4", 4), ("read_s4", 4)):
            read = getattr(decoder, name)
            for offset in (-1, 1, True, 0.0):
                with self.subTest(name=name, offset=offset):
                    with self.assertRaises(ValueError):
                        read(b"\xff" * width, offset)
            self.assertEqual(read(b"\xff" * width, 0), -1 if "s" in name[5:] else (1 << (width * 8)) - 1)

    def test_integer_operands_pass_through_cfg_and_soot(self):
        # iipush -10; istore 0; iinc 0 -1; iload 0; ireturn
        source = method(b"\x14\xff\xff\xff\xf6\x2a\x00\x5a\x00\xff\x17\x00\x79",
                        returns=INT, locals_=2)
        ir = IRBuilder().build(source, cfg=build_cfg(source))
        operations = [op for block in ir.blocks for op in block.operations]
        self.assertEqual(operations[0].args, (-10,))
        self.assertEqual(operations[2].args, (0, -1))
        symbols = SymbolTable.from_dict({"package_aid": "0102030405", "package_version": [1, 0]})
        soot = SootIRBuilder(symbols).build(JVMLikeIRBuilder().build(ir))
        self.assertTrue(soot.units)


class SwitchDecodingTests(unittest.TestCase):
    def test_all_switch_forms_preserve_signed_values_and_opcode_relative_targets(self):
        for name in SWITCHES:
            with self.subTest(name=name):
                raw = switch_bytes(name, default=-2, keys=(-1, 0), targets=(-1, 3))
                items = decoder.parse_bytecode(b"\x00\x00" + raw + b"\x00")
                switch = items[2]
                self.assertEqual((switch.offset, items[3].offset), (2, 2 + len(raw)))
                self.assertEqual(switch.operands["default"], 0)
                if "table" in name:
                    self.assertEqual((switch.operands["low"], switch.operands["high"]), (-1, 0))
                    self.assertEqual(switch.operands["jumps"], [1, 5])
                else:
                    self.assertEqual(switch.operands["npairs"], 2)
                    self.assertEqual(switch.operands["pairs"], [(-1, 1), (0, 5)])

    def test_lookup_zero_pairs_and_counts_above_one_byte(self):
        for name in ("slookupswitch", "ilookupswitch"):
            for count in (0, 256):
                with self.subTest(name=name, count=count):
                    raw = switch_bytes(name, keys=tuple(range(count)), targets=(0,) * count)
                    switch, tail = decoder.parse_bytecode(raw + b"\x00")
                    self.assertEqual(switch.operands["npairs"], count)
                    self.assertEqual(len(switch.operands["pairs"]), count)
                    self.assertEqual(tail.offset, 5 + count * (4 if name.startswith("s") else 6))

    def test_lookup_high_bit_is_an_unsigned_count_and_requires_the_whole_table(self):
        for name, entry_size in (("slookupswitch", 4), ("ilookupswitch", 6)):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    decoder.parse_bytecode(bytes([SWITCHES[name], 0, 0, 0x80, 0]))
                self.assertEqual((caught.exception.offset, caught.exception.needed, caught.exception.available),
                                 (5, 32768 * entry_size, 0))

    def test_every_truncated_switch_header_or_table_is_rejected(self):
        for name in SWITCHES:
            raw = switch_bytes(name)
            for end in range(1, len(raw)):
                with self.subTest(name=name, length=end):
                    with self.assertRaises(ValueError) as caught:
                        decoder.parse_bytecode(b"\x00\x00" + raw[:end])
                    self.assertIn(name, caught.exception.context)

    def test_direct_switch_parsers_validate_offset_opcode_and_header(self):
        for name in SWITCHES:
            parse = getattr(decoder, "parse_" + name)
            raw = switch_bytes(name)
            for data, offset in ((b"", 0), (raw, -1), (raw, True), (raw, len(raw)),
                                 (b"\x00" + raw[1:], 0)):
                with self.subTest(name=name, data=data, offset=offset):
                    with self.assertRaises(ValueError):
                        parse(data, offset)

    def test_table_ranges_are_ordered_and_huge_tables_fail_before_iteration(self):
        for name in ("stableswitch", "itableswitch"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "high < low"):
                    decoder.parse_bytecode(switch_bytes(name, keys=(1, -1), targets=()))
        raw = b"\x74\x00\x00" + struct.pack(">ii", -(1 << 31), (1 << 31) - 1)
        with self.assertRaises(ValueError) as caught:
            decoder.parse_bytecode(raw)
        self.assertEqual(caught.exception.needed, (1 << 32) * 2)

    def test_lookup_keys_must_be_strictly_increasing(self):
        for name in ("slookupswitch", "ilookupswitch"):
            for keys in ((0, 0), (1, -1)):
                with self.subTest(name=name, keys=keys):
                    with self.assertRaisesRegex(ValueError, "strictly increasing"):
                        decoder.parse_bytecode(switch_bytes(name, keys=keys))

    def test_all_four_binary_switches_agree_with_cfg_ir_and_soot(self):
        for name in SWITCHES:
            with self.subTest(name=name):
                size = len(switch_bytes(name))
                raw = switch_bytes(name, default=size + 2, targets=(size, size + 1))
                source = method(bytes([0x03 if name.startswith("s") else 0x0a]) + raw + b"\x7a\x7a\x7a")
                cfg = build_cfg(source)
                report = Verifier().verify(source)
                self.assertTrue(report.success, report.to_text())
                ir = IRBuilder().build(source, cfg=cfg)
                self.assertEqual(ir, IRBuilder().build(source))
                op = next(op for block in ir.blocks for op in block.operations if op.op == Op.SWITCH)
                self.assertEqual(op.cases, ((-1, 1 + size), (0, 2 + size)))
                self.assertEqual(op.targets, (3 + size, 1 + size, 2 + size))
                symbols = SymbolTable.from_dict({"package_aid": "0102030405", "package_version": [1, 0]})
                soot = SootIRBuilder(symbols).build(JVMLikeIRBuilder().build(ir))
                self.assertTrue(soot.units)


if __name__ == "__main__":
    unittest.main()
