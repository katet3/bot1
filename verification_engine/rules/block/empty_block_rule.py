# rules/block/empty_block_rule.py

from verification_engine.engine.rule_base import Rule
from verification_engine.model.verification_error import VerificationError


class EmptyBlockRule(Rule):

    name = "EMPTY_BLOCK"

    def check(self, cfg, ctx):

        errors = []

        for block in cfg.blocks:

            if not block.instructions:

                errors.append(
                    VerificationError(
                        code="EMPTY_BLOCK",
                        message=f"Block B{block.id} is empty"
                    )
                )

        return errors