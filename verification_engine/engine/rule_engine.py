# verification_engine/engine/rule_engine.py

from verification_engine.model.verification_report import VerificationReport


class RuleEngine:

    def __init__(self, rules):
        self.rules = rules

    def run(self, cfg):

        context = self._build_context(cfg)

        report = VerificationReport()

        for rule in self.rules:

            errors = rule.check(cfg, context)

            if errors:
                report.extend(errors)

        return report

    def _build_context(self, cfg):
        """Index valid edges for traversal while retaining all raw diagnostics."""

        adjacency = {}
        reverse = {}
        block_map = {}

        for b in cfg.blocks:
            block_map[b.id] = b
            adjacency[b.id] = []
            reverse[b.id] = []

        for e in cfg.edges:
            # Do not invent vertices or index half an edge. EdgeTargetRule still
            # inspects every original edge via cfg.edges / context.edge_list.
            if e.source not in block_map or e.target not in block_map:
                continue
            adjacency[e.source].append(e.target)
            reverse[e.target].append(e.source)

        return __import__("verification_engine.engine.rule_context", fromlist=["RuleContext"]).RuleContext(
            block_map=block_map,
            edge_list=cfg.edges,
            adjacency=adjacency,
            reverse_adjacency=reverse
        )
