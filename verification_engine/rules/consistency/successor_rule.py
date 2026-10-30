# rules/consistency/successor_rule.py

from verification_engine.engine.rule_base import Rule
from verification_engine.model.verification_error import VerificationError


class SuccessorConsistencyRule(Rule):

    name = "SUCCESSOR_CONSISTENCY"

    def check(self, cfg, ctx):

        errors = []

        for block in cfg.blocks:

            expected = set(ctx.adjacency.get(block.id, []))
            actual = set(getattr(block, "successors", []))

            if expected != actual:

                errors.append(
                    VerificationError(
                        error_type="SUCCESSOR_MISMATCH",
                        message=(
                            f"Block B{block.id}: "
                            f"expected {expected}, actual {actual}"
                        )
                    )
                )

        return errors
