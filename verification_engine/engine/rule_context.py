# verification_engine/engine/rule_context.py

from dataclasses import dataclass


@dataclass
class RuleContext:
    block_map: dict
    edge_list: list
    adjacency: dict
    reverse_adjacency: dict