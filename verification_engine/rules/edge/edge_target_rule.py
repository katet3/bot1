# rules/edge/edge_target_rule.py

from verification_engine.engine.rule_base import Rule
from verification_engine.model.verification_error import VerificationError


class EdgeTargetRule(Rule):

    name = "EDGE_TARGET"

    def check(self, cfg, ctx):

        errors = []

        block_ids = set(ctx.block_map.keys())

        for e in cfg.edges:

            if e.source not in block_ids:
                errors.append(
                    VerificationError(
                        code="INVALID_EDGE_SOURCE",
                        message=f"B{e.source} does not exist"
                    )
                )

            if e.target not in block_ids:
                errors.append(
                    VerificationError(
                        code="INVALID_EDGE_TARGET",
                        message=f"B{e.target} does not exist"
                    )
                )

        return errors