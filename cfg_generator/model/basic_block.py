# cfg_generator/model/basic_block.py

from dataclasses import dataclass
from cap_decompile.model.method_info import Instruction


@dataclass
class BasicBlock:
    id: int

    start_offset: int
    end_offset: int

    instructions: list[Instruction]

    successors: list[int]
    predecessors: list[int]

    is_entry: bool = False
    is_exit: bool = False
    is_exception_handler: bool = False