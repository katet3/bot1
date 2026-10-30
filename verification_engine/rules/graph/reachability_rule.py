# rules/graph/reachability_rule.py

from collections import deque
from verification_engine.engine.rule_base import Rule
from verification_engine.model.verification_error import VerificationError


class ReachabilityRule(Rule):

    name = "REACHABILITY"

    def check(self, cfg, ctx):

        entry = [b for b in cfg.blocks if b.is_entry]

        if len(entry) != 1:
            return [
                VerificationError(
                    error_type="INVALID_ENTRY",
                    message="Expected exactly one entry block"
                )
            ]

        start = entry[0].id

        visited = set()
        q = deque([start])

        while q:
            n = q.popleft()
            if n in visited:
                continue
            visited.add(n)
            q.extend(ctx.adjacency.get(n, []))

        errors = []

        for b in cfg.blocks:
            if b.id not in visited:
                errors.append(
                    VerificationError(
                        error_type="UNREACHABLE_BLOCK",
                        message=f"Block B{b.id} is unreachable"
                    )
                )

        return errors
