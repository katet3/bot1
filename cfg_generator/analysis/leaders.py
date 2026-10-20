# cfg_generator/analysis/leaders.py

from cap_decompile.model.method_info import Method

from cfg_generator.utils.instruction_utils import (
    is_conditional_branch,
    is_unconditional_branch,
    is_switch
)


def find_leaders(method: Method) -> list[int]:

    instructions = method.instructions

    if not instructions:
        return []

    leaders = {
        instructions[0].offset
    }

    for i, ins in enumerate(instructions):

        mnemonic = ins.mnemonic

        if is_conditional_branch(mnemonic):

            target = ins.operands[0]

            leaders.add(target)

            if i + 1 < len(instructions):
                leaders.add(
                    instructions[i + 1].offset
                )

        elif is_unconditional_branch(mnemonic):

            target = ins.operands[0]

            leaders.add(target)

        elif is_switch(mnemonic):
            operands = ins.operands
            leaders.add(operands["default"])
            
            # tableswitch: список jumps
            if "jumps" in operands:
                for target in operands["jumps"]:
                    leaders.add(target)
            # lookupswitch: список pairs (каждый элемент — [значение, смещение])
            elif "pairs" in operands:
                for _, target in operands["pairs"]:
                    leaders.add(target)

    return sorted(leaders)