# cfg_generator/analysis/leaders.py

from cfg_generator.analysis.handlers import validated_exception_regions

from cfg_generator.utils.instruction_utils import (
    is_conditional_branch,
    is_unconditional_branch,
    is_switch,
    is_terminator,
    reject_unsupported_control_flow,
)


def find_leaders(method) -> list[int]:
    """Find ordinary branch leaders and validated exception-region boundaries."""

    instructions = method.instructions
    reject_unsupported_control_flow(instructions)
    regions = validated_exception_regions(method)

    if not instructions:
        return []

    leaders = {
        instructions[0].offset
    }

    for region in regions:
        leaders.update((region.start, region.target))
        if region.end < len(method.bytecodes):
            leaders.add(region.end)

    for i, ins in enumerate(instructions):

        mnemonic = ins.mnemonic

        if is_conditional_branch(mnemonic) or is_unconditional_branch(mnemonic):

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

        # Keep code after every terminator separate, even when unreachable.
        # For return/athrow this boundary does not imply a normal edge.
        if is_terminator(mnemonic) and i + 1 < len(instructions):
            leaders.add(instructions[i + 1].offset)

    return sorted(leaders)
