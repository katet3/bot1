# cfg_generator/utils/instruction_utils.py

CONDITIONAL_BRANCHES = {
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

    # int compare
    "if_icmpeq",
    "if_icmpne",
    "if_icmplt",
    "if_icmple",
    "if_icmpgt",
    "if_icmpge",

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

TERMINATORS = (
    CONDITIONAL_BRANCHES
    | UNCONDITIONAL_BRANCHES
    | SWITCH_INSTRUCTIONS
    | RETURNS
)


def is_conditional_branch(mnemonic: str) -> bool:
    return mnemonic in CONDITIONAL_BRANCHES


def is_unconditional_branch(mnemonic: str) -> bool:
    return mnemonic in UNCONDITIONAL_BRANCHES


def is_switch(mnemonic: str) -> bool:
    return mnemonic in SWITCH_INSTRUCTIONS


def is_return(mnemonic: str) -> bool:
    return mnemonic in RETURNS


def is_terminator(mnemonic: str) -> bool:
    return mnemonic in TERMINATORS