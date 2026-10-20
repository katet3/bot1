from verification_engine.engine.rule_engine import RuleEngine

from verification_engine.rules.block.empty_block_rule import EmptyBlockRule
from verification_engine.rules.graph.reachability_rule import ReachabilityRule
from verification_engine.rules.edge.edge_target_rule import EdgeTargetRule
from verification_engine.rules.consistency.successor_rule import SuccessorConsistencyRule

from cfg_generator.builder import build_cfg


class Verifier:

    def __init__(self):

        self.engine = RuleEngine([
            EmptyBlockRule(),
            ReachabilityRule(),
            EdgeTargetRule(),
            SuccessorConsistencyRule()
        ])

    def verify(self, method):

        cfg = self._build_cfg(method)

        return self.engine.run(cfg)

    def _build_cfg(self, method):
        return build_cfg(method)