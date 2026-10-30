# verification_engine/engine/rule_context.py

from dataclasses import dataclass


@dataclass
class RuleContext:
    """Shared CFG indexes for rules.

    edge_list retains all original edges, including malformed endpoints.
    block_map, adjacency and reverse_adjacency have only declared block IDs.
    Both adjacency indexes include an edge only when both endpoints exist;
    valid edge order and multiplicity are preserved. Context construction does
    not repair the input CFG or replace endpoint validation by a rule.
    """

    block_map: dict
    edge_list: list
    adjacency: dict
    reverse_adjacency: dict
