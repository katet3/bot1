# cfg_generator/model/cfg.py
from dataclasses import dataclass, field

from .basic_block import BasicBlock
from .edge import CFGEdge


@dataclass
class CFG:
    method_name: str

    entry_block: int

    blocks: list[BasicBlock]
    edges: list[CFGEdge]

    offset_to_block: dict[int, int] = field(default_factory=dict)