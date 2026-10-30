"""D-03: malformed endpoints remain diagnosable through the real rule engine."""
from copy import deepcopy
import unittest

from cap_decompile.model.method_info import Instruction
from cfg_generator.model.basic_block import BasicBlock
from cfg_generator.model.cfg import CFG
from cfg_generator.model.edge import CFGEdge, EdgeType
from verification_engine.engine.rule_base import Rule
from verification_engine.engine.rule_engine import RuleEngine
from verification_engine.model.verification_error import VerificationError
from verification_engine.rules.edge.edge_target_rule import EdgeTargetRule
from verification_engine.verifier import Verifier


def graph(block_ids=(0,), edges=(), successors=None):
    successors = {} if successors is None else successors
    blocks = []
    for index, block_id in enumerate(block_ids):
        offset = index * 4
        blocks.append(BasicBlock(
            id=block_id,
            start_offset=offset,
            end_offset=offset,
            instructions=[Instruction(offset, 0x00, "nop", [])],
            successors=list(successors.get(block_id, ())),
            predecessors=[],
            is_entry=index == 0,
        ))
    return CFG("endpoint_checks", block_ids[0] if block_ids else 0, blocks, list(edges))


class CaptureContext(Rule):
    def __init__(self):
        super().__init__()
        self.context = None

    def check(self, cfg, context):
        self.context = context
        return []


class InvalidEdgeTests(unittest.TestCase):
    def check_endpoints(self, cfg):
        # Capture runs before EdgeTargetRule: context must already be safe.
        capture = CaptureContext()
        report = RuleEngine([capture, EdgeTargetRule()]).run(cfg)
        self.assertIsNotNone(capture.context)
        self.assertEqual(capture.context.edge_list, cfg.edges)
        self.assertTrue(all(isinstance(error, VerificationError) for error in report.errors))
        return report, capture.context

    def assert_errors(self, report, expected):
        self.assertEqual([(e.error_type, e.message) for e in report.errors], expected)
        self.assertEqual(report.success, not expected)
        for error_type, message in expected:
            self.assertIn(f" - {error_type}: {message}", report.to_text())

    def test_missing_source_does_not_enter_reverse_adjacency(self):
        cfg = graph(edges=[CFGEdge(9, 0, EdgeType.GOTO)])
        report, context = self.check_endpoints(cfg)
        self.assert_errors(report, [("INVALID_EDGE_SOURCE", "B9 does not exist")])
        self.assertEqual(context.adjacency, {0: []})
        self.assertEqual(context.reverse_adjacency, {0: []})
        self.assertEqual(set(context.block_map), {0})

    def test_missing_target_does_not_enter_forward_adjacency(self):
        cfg = graph(edges=[CFGEdge(0, 9, EdgeType.GOTO)])
        report, context = self.check_endpoints(cfg)
        self.assert_errors(report, [("INVALID_EDGE_TARGET", "B9 does not exist")])
        self.assertEqual(context.adjacency, {0: []})
        self.assertEqual(context.reverse_adjacency, {0: []})
        self.assertEqual(set(context.block_map), {0})

    def test_both_missing_endpoints_are_reported(self):
        cfg = graph(edges=[CFGEdge(8, 9, EdgeType.GOTO)])
        report, context = self.check_endpoints(cfg)
        self.assert_errors(report, [
            ("INVALID_EDGE_SOURCE", "B8 does not exist"),
            ("INVALID_EDGE_TARGET", "B9 does not exist"),
        ])
        self.assertEqual(context.adjacency, {0: []})
        self.assertEqual(context.reverse_adjacency, {0: []})

    def test_edges_in_an_empty_graph_reach_all_registered_rules(self):
        cfg = graph(block_ids=(), edges=[CFGEdge(0, 1, EdgeType.GOTO)])
        report = Verifier().engine.run(cfg)
        self.assert_errors(report, [
            ("INVALID_ENTRY", "Expected exactly one entry block"),
            ("INVALID_EDGE_SOURCE", "B0 does not exist"),
            ("INVALID_EDGE_TARGET", "B1 does not exist"),
        ])
        self.assertEqual(report.summary(), "Verification FAILED (3 errors)")

    def test_valid_noncontiguous_ids_cycles_and_parallel_edges_are_preserved(self):
        cfg = graph(block_ids=(0, 7), edges=[
            CFGEdge(0, 0, EdgeType.GOTO),
            CFGEdge(0, 7, EdgeType.GOTO),
            CFGEdge(0, 7, EdgeType.EXCEPTION),
            CFGEdge(7, 0, EdgeType.GOTO),
        ], successors={0: [0, 7], 7: [0]})
        report, context = self.check_endpoints(cfg)
        self.assert_errors(report, [])
        self.assertEqual(context.adjacency, {0: [0, 7, 7], 7: [0]})
        self.assertEqual(context.reverse_adjacency, {0: [0, 7], 7: [0, 0]})
        self.assertTrue(Verifier().engine.run(cfg).success)

    def test_mixed_edges_preserve_valid_paths_and_all_raw_diagnostics(self):
        cfg = graph(block_ids=(0, 1, 2), edges=[
            CFGEdge(0, 1, EdgeType.GOTO),
            CFGEdge(9, 0, EdgeType.GOTO),
            CFGEdge(1, 9, EdgeType.GOTO),
            CFGEdge(1, 2, EdgeType.GOTO),
        ], successors={0: [1], 1: [2]})
        report, context = self.check_endpoints(cfg)
        expected = [
            ("INVALID_EDGE_SOURCE", "B9 does not exist"),
            ("INVALID_EDGE_TARGET", "B9 does not exist"),
        ]
        self.assert_errors(report, expected)
        self.assertEqual(context.adjacency, {0: [1], 1: [2], 2: []})
        self.assertEqual(context.reverse_adjacency, {0: [], 1: [0], 2: [1]})
        self.assert_errors(Verifier().engine.run(cfg), expected)

    def test_nonexistent_block_cannot_connect_two_real_blocks(self):
        cfg = graph(block_ids=(0, 1), edges=[
            CFGEdge(0, 9, EdgeType.GOTO), CFGEdge(9, 1, EdgeType.GOTO),
        ], successors={0: [9]})
        report = Verifier().engine.run(cfg)
        self.assert_errors(report, [
            ("UNREACHABLE_BLOCK", "Block B1 is unreachable"),
            ("INVALID_EDGE_TARGET", "B9 does not exist"),
            ("INVALID_EDGE_SOURCE", "B9 does not exist"),
            ("SUCCESSOR_MISMATCH", "Block B0: expected set(), actual {9}"),
        ])

    def test_invalid_successor_metadata_is_not_silently_repaired(self):
        cfg = graph(block_ids=(0, 1), edges=[
            CFGEdge(0, 1, EdgeType.GOTO), CFGEdge(0, 9, EdgeType.GOTO),
        ], successors={0: [1, 9]})
        report = Verifier().engine.run(cfg)
        self.assertFalse(report.success)
        self.assertEqual([e.error_type for e in report.errors], [
            "INVALID_EDGE_TARGET", "SUCCESSOR_MISMATCH",
        ])
        self.assertEqual(cfg.blocks[0].successors, [1, 9])

    def test_context_construction_does_not_modify_the_input_cfg(self):
        cfg = graph(block_ids=(0, 1), edges=[
            CFGEdge(0, 1, EdgeType.GOTO), CFGEdge(0, 1, EdgeType.EXCEPTION),
            CFGEdge(0, 9, EdgeType.GOTO), CFGEdge(8, 1, EdgeType.GOTO),
        ], successors={0: [1, 9]})
        original = deepcopy(cfg)
        report, context = self.check_endpoints(cfg)
        self.assertFalse(report.success)
        self.assertEqual(cfg, original)
        self.assertEqual(context.edge_list, original.edges)

    def test_single_entry_with_no_edges_still_passes(self):
        cfg = graph()
        report, context = self.check_endpoints(cfg)
        self.assert_errors(report, [])
        self.assertEqual(context.adjacency, {0: []})
        self.assertEqual(context.reverse_adjacency, {0: []})
        self.assertEqual(Verifier().engine.run(cfg).to_text(), "Verification PASSED (0 errors)")


if __name__ == "__main__":
    unittest.main()
