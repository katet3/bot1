"""D-05: decoded control flow, block boundaries and typed IR must agree."""
from types import SimpleNamespace
import unittest

from cap_decompile.model.method_info import Instruction, OPCODES, parse_bytecode
from cfg_generator.analysis.leaders import find_leaders
from cfg_generator.builder import build_cfg
from cfg_generator.utils import instruction_utils as flow
from jcvm_ir import Handler, INT, IRBuilder, MethodInput, Op, REF, SHORT, Signature, VOID
from jcvm_ir.lowering import lower
from jvm_like_ir import JVMLikeIRBuilder
from soot_ir import SootIRBuilder, SymbolTable
from verification_engine.verifier import Verifier


CODES = {spec[0]: code for code, spec in OPCODES.items()}
CONDITIONALS = sorted(name for name in CODES if name.startswith("if"))
SWITCHES = ("stableswitch", "itableswitch", "slookupswitch", "ilookupswitch")
RETURNS = ("return", "sreturn", "ireturn", "areturn")


def opcodes(*names):
    return bytes(CODES[name] for name in names)


def method(body, handlers=(), returns=VOID):
    return MethodInput(
        "0102030405/class_0/method_0", 0, 0, body, parse_bytecode(body),
        2, 0, 0, handlers, Signature((), returns), True,
    )


def branch_method(name, *, backward=False, padding=0, same_target=False):
    base = name.removesuffix("_w")
    if base.startswith("if_acmp"):
        prefix = opcodes("aconst_null", "aconst_null")
    elif base in ("ifnull", "ifnonnull"):
        prefix = opcodes("aconst_null")
    elif base.startswith("if_scmp"):
        prefix = opcodes("sconst_0", "sconst_0")
    else:
        prefix = opcodes("sconst_0")
    width = OPCODES[CODES[name]][1]
    if backward:
        prefix = opcodes("nop") * padding + prefix
    offset = len(prefix)
    fallthrough = offset + 1 + width
    target = 0 if backward else fallthrough + (0 if same_target else padding + 1)
    branch = opcodes(name) + (target - offset).to_bytes(width, "big", signed=True)
    tail = opcodes("return") if backward or same_target else (
        opcodes("nop") * padding + opcodes("return", "return")
    )
    return method(prefix + branch + tail), offset, target, fallthrough


def edges_at_offsets(cfg):
    starts = {block.id: block.start_offset for block in cfg.blocks}
    return [(starts[edge.source], starts[edge.target], edge.edge_type.name)
            for edge in cfg.edges]


def soot_from(ir):
    symbols = SymbolTable.from_dict({
        "package_aid": "0102030405", "package_version": [1, 0],
    })
    return SootIRBuilder(symbols).build(JVMLikeIRBuilder().build(ir))


class ControlFlowTests(unittest.TestCase):
    def assert_ir_agrees(self, source, cfg):
        ir = IRBuilder().build(source, cfg=cfg)
        self.assertEqual(ir, IRBuilder().build(source))
        return ir

    def test_every_decoded_conditional_is_classified_and_lowered_as_a_branch(self):
        self.assertEqual(len(CONDITIONALS), 32)
        self.assertEqual(len([name for name in CONDITIONALS if name.endswith("_w")]), 16)
        self.assertEqual(flow.CONDITIONAL_BRANCHES, set(CONDITIONALS))
        for name in CONDITIONALS:
            with self.subTest(name=name):
                self.assertTrue(flow.is_conditional_branch(name))
                self.assertTrue(flow.is_terminator(name))
                operation, size = lower(Instruction(0, CODES[name], name, [0]), None)
                self.assertEqual(operation.op, Op.BRANCH)
                self.assertEqual(size, 1 + OPCODES[CODES[name]][1])

    def test_other_supported_terminators_match_decoded_forms(self):
        for name in ("goto", "goto_w", *SWITCHES, *RETURNS, "athrow"):
            with self.subTest(name=name):
                self.assertIn(name, CODES)
                self.assertTrue(flow.is_terminator(name))
        self.assertTrue(flow.is_throw("athrow"))
        self.assertFalse(flow.is_return("athrow"))

    def test_wide_nonbranches_and_unknown_forms_are_not_misclassified(self):
        for name in ("sinc_w", "iinc_w", "getfield_a_w", "putfield_s_w", "nop",
                     "if_unknown_w", "ifeq_w_w", "return_w", "athrow_w", "if_icmpeq"):
            with self.subTest(name=name):
                self.assertFalse(flow.is_conditional_branch(name))
                self.assertFalse(flow.is_terminator(name))

    def test_instruction_after_every_supported_terminator_is_a_leader(self):
        # Already-decoded metadata: instruction lengths do not matter to leader discovery.
        for name in (*CONDITIONALS, "goto", "goto_w", *SWITCHES, *RETURNS, "athrow"):
            operands = [20]
            if name in SWITCHES:
                operands = {"default": 20, "low": 0, "high": 1, "jumps": [20, 20]}
                if "lookup" in name:
                    operands = {"default": 20, "npairs": 2, "pairs": [(0, 20), (1, 20)]}
            elif name in (*RETURNS, "athrow"):
                operands = []
            source = SimpleNamespace(instructions=[
                Instruction(0, CODES[name], name, operands),
                Instruction(10, CODES["nop"], "nop", []),
                Instruction(20, CODES["return"], "return", []),
            ])
            with self.subTest(name=name):
                self.assertIn(10, find_leaders(source))

    def test_all_conditional_forms_have_true_and_false_successors(self):
        for name in CONDITIONALS:
            with self.subTest(name=name):
                source, offset, target, fallthrough = branch_method(name)
                self.assertEqual(next(i for i in source.instructions if i.offset == offset).operands,
                                 [target])
                cfg = build_cfg(source)
                self.assertEqual([b.start_offset for b in cfg.blocks], [0, fallthrough, target])
                self.assertEqual(edges_at_offsets(cfg), [
                    (0, target, "CONDITIONAL_TRUE"), (0, fallthrough, "CONDITIONAL_FALSE"),
                ])
                report = Verifier().verify(source)
                self.assertTrue(report.success, report.to_text())
                self.assert_ir_agrees(source, cfg)

    def test_all_conditional_forms_preserve_backward_targets(self):
        for name in CONDITIONALS:
            with self.subTest(name=name):
                source, offset, target, fallthrough = branch_method(name, backward=True, padding=4)
                self.assertEqual(target, 0)
                self.assertEqual(next(i for i in source.instructions if i.offset == offset).operands, [0])
                cfg = build_cfg(source)
                self.assertEqual(edges_at_offsets(cfg), [
                    (0, 0, "CONDITIONAL_TRUE"), (0, fallthrough, "CONDITIONAL_FALSE"),
                ])
                self.assert_ir_agrees(source, cfg)

    def test_wide_signed_offsets_beyond_one_byte_work_in_both_directions(self):
        for name in (name for name in CONDITIONALS if name.endswith("_w")):
            for backward in (False, True):
                with self.subTest(name=name, backward=backward):
                    source, offset, target, fallthrough = branch_method(name, backward=backward, padding=160)
                    self.assertGreater(abs(target - offset), 127)
                    cfg = build_cfg(source)
                    self.assertEqual(edges_at_offsets(cfg), [
                        (0, target, "CONDITIONAL_TRUE"), (0, fallthrough, "CONDITIONAL_FALSE"),
                    ])
                    self.assert_ir_agrees(source, cfg)

    def test_same_target_keeps_two_distinct_conditional_edges(self):
        for name in CONDITIONALS:
            with self.subTest(name=name):
                source, _, target, fallthrough = branch_method(name, same_target=True)
                self.assertEqual(target, fallthrough)
                cfg = build_cfg(source)
                self.assertEqual(edges_at_offsets(cfg), [
                    (0, target, "CONDITIONAL_TRUE"), (0, target, "CONDITIONAL_FALSE"),
                ])
                self.assert_ir_agrees(source, cfg)

    def test_goto_widths_have_no_fallthrough(self):
        for name in ("goto", "goto_w"):
            with self.subTest(name=name):
                width = OPCODES[CODES[name]][1]
                target = 1 + width + 2
                body = opcodes("nop", name) + (width + 2).to_bytes(width, "big", signed=True)
                source = method(body + opcodes("return", "return"))
                cfg = build_cfg(source)
                self.assertEqual([b.start_offset for b in cfg.blocks], [0, target - 1, target])
                self.assertEqual(edges_at_offsets(cfg), [(0, target, "GOTO")])
                self.assert_ir_agrees(source, cfg)

    def test_all_returns_end_the_block_without_normal_successors(self):
        for name, prefix, returns in (
            ("return", b"", VOID), ("sreturn", opcodes("sconst_0"), SHORT),
            ("ireturn", opcodes("iconst_0"), INT), ("areturn", opcodes("aconst_null"), REF),
        ):
            with self.subTest(name=name):
                part = prefix + opcodes(name)
                source = method(part + part, returns=returns)
                cfg = build_cfg(source)
                self.assertEqual([b.start_offset for b in cfg.blocks], [0, len(part)])
                self.assertEqual(cfg.edges, [])
                self.assert_ir_agrees(source, cfg)

    def test_all_switch_forms_keep_default_and_shared_cases_without_fallthrough(self):
        # Exercise CFG's decoded-instruction contract independently of binary switch parsing.
        for name in SWITCHES:
            operands = {"default": 20, "low": -1, "high": 0, "jumps": [20, 20]}
            if "lookup" in name:
                operands = {"default": 20, "npairs": 2, "pairs": [(-1, 20), (0, 20)]}
            source = SimpleNamespace(token=0, instructions=[
                Instruction(0, CODES[name], name, operands),
                Instruction(10, CODES["return"], "return", []),
                Instruction(20, CODES["return"], "return", []),
            ])
            with self.subTest(name=name):
                cfg = build_cfg(source)
                self.assertEqual([b.start_offset for b in cfg.blocks], [0, 10, 20])
                self.assertEqual(edges_at_offsets(cfg), [(0, 20, "SWITCH")] * 3)

    def test_athrow_does_not_make_following_code_reachable(self):
        source = method(opcodes("aconst_null", "athrow", "return"))
        cfg = build_cfg(source)
        self.assertEqual([b.start_offset for b in cfg.blocks], [0, 2])
        self.assertEqual(cfg.edges, [])
        self.assertTrue(cfg.blocks[0].is_exit)
        self.assert_ir_agrees(source, cfg)
        report = Verifier().verify(source)
        self.assertEqual([e.error_type for e in report.errors], ["UNREACHABLE_BLOCK"])

    def test_athrow_has_only_an_exception_edge_to_an_adjacent_handler(self):
        source = method(opcodes("aconst_null", "athrow", "pop", "return"),
                        (Handler(0, 2, 2, 0, True),))
        cfg = build_cfg(source)
        self.assertEqual(edges_at_offsets(cfg), [(0, 2, "EXCEPTION")])
        self.assertFalse(cfg.blocks[0].is_exit)
        ir = self.assert_ir_agrees(source, cfg)
        self.assertEqual(ir.blocks[1].input_stack, ("reference",))
        self.assertTrue(Verifier().verify(source).success)

    def test_athrow_does_not_fall_through_before_a_nonadjacent_handler(self):
        source = method(opcodes("aconst_null", "athrow", "nop", "return", "pop", "return"),
                        (Handler(0, 2, 4, 0, True),))
        cfg = build_cfg(source)
        self.assertEqual([b.start_offset for b in cfg.blocks], [0, 2, 4])
        self.assertEqual(edges_at_offsets(cfg), [(0, 4, "EXCEPTION")])
        self.assert_ir_agrees(source, cfg)
        self.assertEqual([e.error_type for e in Verifier().verify(source).errors], ["UNREACHABLE_BLOCK"])

    def test_subroutines_are_rejected_with_mnemonic_and_offset(self):
        for name, tail in (("jsr", b"\x00\x03"), ("ret", b"\x00")):
            with self.subTest(name=name):
                source = method(opcodes("nop", name) + tail + opcodes("return"))
                with self.assertRaisesRegex(ValueError, f"Unsupported CFG control flow {name} at 1"):
                    build_cfg(source)

    def test_unsupported_subroutines_are_rejected_even_in_unreachable_code(self):
        for name, tail in (("jsr", b"\x00\x03"), ("ret", b"\x00")):
            with self.subTest(name=name):
                source = method(opcodes("return", name) + tail + opcodes("return"))
                with self.assertRaisesRegex(ValueError, f"Unsupported CFG control flow {name} at 1"):
                    build_cfg(source)

    def test_all_conditional_forms_reach_soot_with_preserved_relations(self):
        for name in CONDITIONALS:
            with self.subTest(name=name):
                source, offset, _, _ = branch_method(name)
                soot = soot_from(self.assert_ir_agrees(source, build_cfg(source)))
                branches = [unit for unit in soot.units if unit.kind == "if"]
                self.assertEqual(len(branches), 1)
                base = name.removesuffix("_w")
                relation = {"ifnull": "eq", "ifnonnull": "ne"}.get(base, base[-2:])
                self.assertEqual((branches[0].offset, branches[0].right.operator), (offset, relation))

    def test_unhandled_athrow_reaches_soot_with_backend_requirement(self):
        source = method(opcodes("aconst_null", "athrow"))
        soot = soot_from(self.assert_ir_agrees(source, build_cfg(source)))
        self.assertEqual([u.offset for u in soot.units if u.kind == "throw"], [1])
        self.assertEqual(soot.traps, ())
        self.assertIn("ordered_exception_dispatch", soot.required_backend_features)

    def test_wide_branch_and_protected_athrow_preserve_traps_in_soot(self):
        # 0: sconst_0; 1: ifeq_w -> 6; 4: aconst_null; 5: athrow;
        # 6: return; 7: handler pop; 8: return.
        body = opcodes("sconst_0", "ifeq_w") + b"\x00\x05" + opcodes(
            "aconst_null", "athrow", "return", "pop", "return",
        )
        source = method(body, (Handler(4, 6, 7, 0, True),))
        cfg = build_cfg(source)
        self.assertEqual(edges_at_offsets(cfg), [
            (0, 6, "CONDITIONAL_TRUE"), (0, 4, "CONDITIONAL_FALSE"), (4, 7, "EXCEPTION"),
        ])
        self.assertTrue(Verifier().verify(source).success)
        soot = soot_from(self.assert_ir_agrees(source, cfg))
        throw = next(u for u in soot.units if u.kind == "throw")
        self.assertEqual((throw.offset, throw.handlers), (5, (0,)))
        self.assertEqual(len(soot.traps), 1)
        trap = soot.traps[0]
        self.assertEqual((trap.priority, trap.exception_type, trap.stop_bit),
                         (0, "java.lang.Throwable", True))
        self.assertTrue(trap.begin <= throw.label < trap.end)
        self.assertIn("ordered_exception_dispatch", soot.required_backend_features)


if __name__ == "__main__":
    unittest.main()
