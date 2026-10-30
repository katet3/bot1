"""D-01: malformed CFGs produce rule diagnostics instead of TypeError.

Rules are exercised directly with an explicit context. Aggregation regressions
(D-02) are covered in test_rule_engine; invalid-edge context construction (D-03)
is covered through the real engine in test_invalid_edges.
"""
import unittest

from cap_decompile.model.method_info import Instruction
from cfg_generator.model.basic_block import BasicBlock
from cfg_generator.model.cfg import CFG
from cfg_generator.model.edge import CFGEdge, EdgeType
from verification_engine.engine.rule_context import RuleContext
from verification_engine.engine.rule_engine import RuleEngine
from verification_engine.model.verification_error import VerificationError
from verification_engine.model.verification_report import VerificationReport
from verification_engine.rules.block.empty_block_rule import EmptyBlockRule
from verification_engine.rules.consistency.successor_rule import SuccessorConsistencyRule
from verification_engine.rules.edge.edge_target_rule import EdgeTargetRule
from verification_engine.rules.graph.reachability_rule import ReachabilityRule


def block(block_id, *, empty=False, entry=False, successors=()):
    offset = block_id * 4
    instructions = [] if empty else [Instruction(offset, 0x00, "nop", [])]
    return BasicBlock(
        id=block_id,
        start_offset=offset,
        end_offset=offset,
        instructions=instructions,
        successors=list(successors),
        predecessors=[],
        is_entry=entry,
    )


def graph(blocks, edges=()):
    cfg = CFG("rule_test", 0, list(blocks), list(edges))
    context = RuleContext(
        block_map={b.id: b for b in blocks},
        edge_list=cfg.edges,
        adjacency={b.id: [e.target for e in edges if e.source == b.id] for b in blocks},
        reverse_adjacency={b.id: [e.source for e in edges if e.target == b.id] for b in blocks},
    )
    return cfg, context


class CFGRuleTests(unittest.TestCase):
    def assert_diagnostics(self, rule, cfg, context, expected):
        errors = rule.check(cfg, context)
        self.assertIsInstance(errors, list)
        self.assertEqual(len(errors), len(expected))
        for error, (error_type, message) in zip(errors, expected):
            self.assertIsInstance(error, VerificationError)
            self.assertEqual(error.error_type, error_type)
            self.assertEqual(error.message, message)
            self.assertEqual(str(error), f"{error_type}: {message}")

        # Check the rule result independently from the engine aggregation tests.
        report = VerificationReport()
        report.extend(errors)
        self.assertEqual(report.success, not expected)
        self.assertEqual(report.has_errors(), bool(expected))
        text = report.to_text()
        for error_type, message in expected:
            self.assertIn(f" - {error_type}: {message}", text)

    def test_empty_blocks_produce_one_diagnostic_each(self):
        cfg, context = graph([block(0, empty=True, entry=True), block(1), block(2, empty=True)])
        self.assert_diagnostics(EmptyBlockRule(), cfg, context, [
            ("EMPTY_BLOCK", "Block B0 is empty"),
            ("EMPTY_BLOCK", "Block B2 is empty"),
        ])

    def test_nonempty_blocks_are_accepted(self):
        cfg, context = graph([block(0, entry=True), block(1)])
        self.assert_diagnostics(EmptyBlockRule(), cfg, context, [])

    def test_missing_entry_produces_invalid_entry(self):
        cfg, context = graph([block(0)])
        self.assert_diagnostics(ReachabilityRule(), cfg, context, [
            ("INVALID_ENTRY", "Expected exactly one entry block"),
        ])

    def test_multiple_entries_produce_invalid_entry(self):
        cfg, context = graph([block(0, entry=True), block(1, entry=True)])
        self.assert_diagnostics(ReachabilityRule(), cfg, context, [
            ("INVALID_ENTRY", "Expected exactly one entry block"),
        ])

    def test_empty_graph_produces_invalid_entry(self):
        cfg, context = graph([])
        self.assert_diagnostics(ReachabilityRule(), cfg, context, [
            ("INVALID_ENTRY", "Expected exactly one entry block"),
        ])

    def test_unreachable_blocks_keep_the_existing_diagnostic(self):
        cfg, context = graph([block(0, entry=True), block(1), block(2)])
        self.assert_diagnostics(ReachabilityRule(), cfg, context, [
            ("UNREACHABLE_BLOCK", "Block B1 is unreachable"),
            ("UNREACHABLE_BLOCK", "Block B2 is unreachable"),
        ])

    def test_reachable_cycle_is_accepted(self):
        cfg, context = graph([block(0, entry=True), block(1)], [
            CFGEdge(0, 1, EdgeType.GOTO), CFGEdge(1, 0, EdgeType.GOTO),
        ])
        self.assert_diagnostics(ReachabilityRule(), cfg, context, [])

    def test_missing_edge_source_produces_invalid_source(self):
        cfg, context = graph([block(0, entry=True)], [CFGEdge(9, 0, EdgeType.GOTO)])
        self.assert_diagnostics(EdgeTargetRule(), cfg, context, [
            ("INVALID_EDGE_SOURCE", "B9 does not exist"),
        ])

    def test_missing_edge_target_produces_invalid_target(self):
        cfg, context = graph([block(0, entry=True)], [CFGEdge(0, 9, EdgeType.GOTO)])
        self.assert_diagnostics(EdgeTargetRule(), cfg, context, [
            ("INVALID_EDGE_TARGET", "B9 does not exist"),
        ])

    def test_both_missing_edge_endpoints_are_reported(self):
        cfg, context = graph([block(0, entry=True)], [CFGEdge(8, 9, EdgeType.GOTO)])
        self.assert_diagnostics(EdgeTargetRule(), cfg, context, [
            ("INVALID_EDGE_SOURCE", "B8 does not exist"),
            ("INVALID_EDGE_TARGET", "B9 does not exist"),
        ])

    def test_valid_edge_endpoints_are_accepted(self):
        cfg, context = graph([block(0, entry=True), block(1)], [
            CFGEdge(0, 1, EdgeType.GOTO), CFGEdge(1, 0, EdgeType.GOTO),
        ])
        self.assert_diagnostics(EdgeTargetRule(), cfg, context, [])

    def test_missing_successor_produces_mismatch(self):
        cfg, context = graph([block(0, entry=True), block(1)], [CFGEdge(0, 1, EdgeType.GOTO)])
        self.assert_diagnostics(SuccessorConsistencyRule(), cfg, context, [
            ("SUCCESSOR_MISMATCH", "Block B0: expected {1}, actual set()"),
        ])

    def test_unexpected_successor_produces_mismatch(self):
        cfg, context = graph([block(0, entry=True, successors=[1]), block(1)])
        self.assert_diagnostics(SuccessorConsistencyRule(), cfg, context, [
            ("SUCCESSOR_MISMATCH", "Block B0: expected set(), actual {1}"),
        ])

    def test_consistent_successors_are_accepted(self):
        cfg, context = graph([block(0, entry=True, successors=[1]), block(1)], [
            CFGEdge(0, 1, EdgeType.GOTO),
        ])
        self.assert_diagnostics(SuccessorConsistencyRule(), cfg, context, [])

    def test_valid_cfg_passes_all_registered_rules_together(self):
        cfg, _ = graph([block(0, entry=True, successors=[1]), block(1)], [
            CFGEdge(0, 1, EdgeType.GOTO),
        ])
        report = RuleEngine([
            EmptyBlockRule(), ReachabilityRule(), EdgeTargetRule(), SuccessorConsistencyRule(),
        ]).run(cfg)
        self.assertTrue(report.success)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.to_text(), "Verification PASSED (0 errors)")


if __name__ == "__main__":
    unittest.main()
