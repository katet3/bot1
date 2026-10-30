"""D-02: aggregate rule diagnostics as a flat, ordered report."""
import unittest

from cfg_generator.model.basic_block import BasicBlock
from cfg_generator.model.cfg import CFG
from verification_engine.engine.rule_base import Rule
from verification_engine.engine.rule_engine import RuleEngine
from verification_engine.model.verification_error import VerificationError
from verification_engine.model.verification_report import VerificationReport
from verification_engine.rules.block.empty_block_rule import EmptyBlockRule
from verification_engine.rules.consistency.successor_rule import SuccessorConsistencyRule
from verification_engine.rules.edge.edge_target_rule import EdgeTargetRule
from verification_engine.rules.graph.reachability_rule import ReachabilityRule


class FixedDiagnosticsRule(Rule):
    def __init__(self, errors):
        super().__init__()
        self.errors = errors

    def check(self, cfg, context):
        return self.errors


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.cfg = CFG("aggregation", 0, [], [])
        self.first = VerificationError("FIRST", "first problem", block_offset=0)
        self.second = VerificationError("SECOND", "second problem", instruction_offset=4)
        self.third = VerificationError("THIRD", "third problem")

    def run_rules(self, *results):
        return RuleEngine([FixedDiagnosticsRule(errors) for errors in results]).run(self.cfg)

    def assert_report(self, report, expected):
        self.assertEqual(report.errors, expected)
        self.assertTrue(all(isinstance(error, VerificationError) for error in report.errors))
        self.assertEqual(report.success, not expected)
        self.assertEqual(report.has_errors(), bool(expected))
        summary = (f"Verification FAILED ({len(expected)} errors)" if expected
                   else "Verification PASSED (0 errors)")
        self.assertEqual(report.summary(), summary)
        text = summary
        if expected:
            text += "\n\nErrors:\n" + "\n".join(f" - {error}" for error in expected)
        self.assertEqual(report.to_text(), text)

    def test_empty_rules_and_clean_results_pass(self):
        self.assert_report(RuleEngine([]).run(self.cfg), [])
        self.assert_report(self.run_rules([], []), [])

    def test_single_diagnostic_is_not_wrapped_in_a_list(self):
        self.assert_report(self.run_rules([self.first]), [self.first])

    def test_all_diagnostics_from_one_rule_are_counted(self):
        self.assert_report(self.run_rules([self.first, self.second]), [self.first, self.second])

    def test_rule_order_and_error_order_survive_empty_rules(self):
        report = self.run_rules([], [self.first, self.second], [], [self.third], [])
        self.assert_report(report, [self.first, self.second, self.third])

    def test_repeated_runs_have_independent_report_lists(self):
        original = [self.first, self.second]
        engine = RuleEngine([FixedDiagnosticsRule(original)])
        first_run = engine.run(self.cfg)
        second_run = engine.run(self.cfg)
        self.assert_report(first_run, original)
        self.assert_report(second_run, original)
        first_run.add_error(self.third)
        self.assert_report(first_run, [self.first, self.second, self.third])
        self.assert_report(second_run, [self.first, self.second])
        self.assertEqual(original, [self.first, self.second])

    def test_real_rules_report_four_violations_as_four_errors(self):
        # Invalid endpoints are covered separately in test_invalid_edges.
        cfg = CFG("malformed_blocks", 0, [
            BasicBlock(0, 0, 0, [], [1], [], is_entry=True),
            BasicBlock(1, 4, 4, [], [], []),
        ], [])
        report = RuleEngine([
            EmptyBlockRule(), ReachabilityRule(), EdgeTargetRule(), SuccessorConsistencyRule(),
        ]).run(cfg)
        self.assert_report(report, [
            VerificationError("EMPTY_BLOCK", "Block B0 is empty"),
            VerificationError("EMPTY_BLOCK", "Block B1 is empty"),
            VerificationError("UNREACHABLE_BLOCK", "Block B1 is unreachable"),
            VerificationError("SUCCESSOR_MISMATCH", "Block B0: expected set(), actual {1}"),
        ])

    def test_merging_engine_reports_preserves_individual_errors(self):
        left = self.run_rules([self.first, self.second])
        right = self.run_rules([self.third])
        merged = VerificationReport()
        merged.merge(left)
        merged.merge(right)
        self.assert_report(merged, [self.first, self.second, self.third])
        self.assert_report(left, [self.first, self.second])
        self.assert_report(right, [self.third])

    def test_add_error_and_extend_accept_single_and_multiple_errors(self):
        report = VerificationReport()
        report.add_error(self.first)
        report.extend([self.second, self.third])
        self.assert_report(report, [self.first, self.second, self.third])

    def test_empty_extend_does_not_reset_success_or_existing_errors(self):
        report = VerificationReport()
        report.extend([])
        self.assert_report(report, [])
        report.extend([self.first])
        report.extend([])
        self.assert_report(report, [self.first])

    def test_merging_clean_report_does_not_reset_failure(self):
        report = VerificationReport()
        report.add_error(self.first)
        report.merge(VerificationReport())
        self.assert_report(report, [self.first])


if __name__ == "__main__":
    unittest.main()
