# cfg_generator/analysis/block_splitter.py

from cfg_generator.model.basic_block import (
    BasicBlock
)

from cfg_generator.utils.instruction_utils import (
    is_terminator
)


def split_basic_blocks(
    instructions,
    leaders
):

    if not instructions:
        return []

    leader_set = set(leaders)

    blocks = []

    current = []
    block_id = 0

    total = len(instructions)

    for i, ins in enumerate(instructions):

        current.append(ins)

        mnemonic = ins.mnemonic

        next_instruction = (
            instructions[i + 1]
            if i + 1 < total
            else None
        )

        should_close = False

        # Block ends on branch/switch/return/throw.
        if is_terminator(mnemonic):
            should_close = True

        # next instruction starts a new leader
        elif (
            next_instruction
            and next_instruction.offset in leader_set
        ):
            should_close = True

        if should_close:

            blocks.append(
                _build_block(
                    block_id,
                    current
                )
            )

            block_id += 1
            current = []

    if current:
        blocks.append(
            _build_block(
                block_id,
                current
            )
        )

    return blocks


def _build_block(
    block_id,
    instructions
):

    return BasicBlock(
        id=block_id,
        start_offset=instructions[0].offset,
        end_offset=instructions[-1].offset,
        instructions=instructions,
        successors=[],
        predecessors=[]
    )
