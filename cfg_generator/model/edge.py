# cfg_generator/model/edge.py

from dataclasses import dataclass

from enum import Enum

class EdgeType(Enum):
    FALLTHROUGH = 1
    CONDITIONAL_TRUE = 2
    CONDITIONAL_FALSE = 3
    GOTO = 4
    SWITCH = 5
    EXCEPTION = 6
    RETURN = 7

@dataclass
class CFGEdge:
    source: int
    target: int
    edge_type: EdgeType