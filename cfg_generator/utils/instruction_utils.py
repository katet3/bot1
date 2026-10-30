"""Shared control-flow classification for the supported JCVM CFG subset."""

BASE_CONDITIONAL_BRANCHES = {
    # base
    "ifeq",
    "ifne",
    "iflt",
    "ifle",
    "ifgt",
    "ifge",

    # null
    "ifnull",
    "ifnonnull",

    # short compare (JavaCard)
    "if_scmpeq",
    "if_scmpne",
    "if_scmplt",
    "if_scmple",
    "if_scmpgt",
    "if_scmpge",

    # ref compare
    "if_acmpeq",
    "if_acmpne",
}

# These 16 decoded conditionals each have an s2-displacement wide form.
# A generic '_w' suffix does not make another opcode a branch.
CONDITIONAL_BRANCHES = BASE_CONDITIONAL_BRANCHES | {
    f"{mnemonic}_w" for mnemonic in BASE_CONDITIONAL_BRANCHES
}

UNCONDITIONAL_BRANCHES = {
    "goto",
    "goto_w",
}

SWITCH_INSTRUCTIONS = {
    "stableswitch",
    "itableswitch",
    "slookupswitch",
    "ilookupswitch",
}

RETURNS = {
    "return",
    "areturn",
    "ireturn",
    "sreturn",
}

THROWS = {"athrow"}

# Decoded, but return-address/subroutine semantics are not implemented in the IR.
UNSUPPORTED_CONTROL_FLOW = {"jsr", "ret"}

TERMINATORS = (
    CONDITIONAL_BRANCHES
    | UNCONDITIONAL_BRANCHES
    | SWITCH_INSTRUCTIONS
    | RETURNS
    | THROWS
)


def is_conditional_branch(mnemonic: str) -> bool:
    return mnemonic in CONDITIONAL_BRANCHES


def is_unconditional_branch(mnemonic: str) -> bool:
    return mnemonic in UNCONDITIONAL_BRANCHES


def is_switch(mnemonic: str) -> bool:
    return mnemonic in SWITCH_INSTRUCTIONS


def is_return(mnemonic: str) -> bool:
    return mnemonic in RETURNS


def is_throw(mnemonic: str) -> bool:
    return mnemonic in THROWS


def is_terminator(mnemonic: str) -> bool:
    return mnemonic in TERMINATORS


def reject_unsupported_control_flow(instructions) -> None:
    """Fail before CFG construction instead of treating a subroutine as fallthrough."""
    for instruction in instructions:
        if instruction.mnemonic in UNSUPPORTED_CONTROL_FLOW:
            raise ValueError(
                f"Unsupported CFG control flow {instruction.mnemonic} at {instruction.offset}: "
                "subroutine return-address semantics are not implemented"
            )
