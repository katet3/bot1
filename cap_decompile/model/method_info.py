# model/method_info.py

from dataclasses import dataclass
from typing import Any, Dict, List, Union


# =========================================================
# DATA STRUCTURES
# =========================================================

@dataclass
class Instruction:
    offset: int
    opcode: int
    mnemonic: str
    operands: Union[List[Any], Dict[str, Any]]


from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExceptionHandler:
    start_offset: int
    stop_bit: bool
    active_length: int
    handler_offset: int
    catch_type_index: int


@dataclass
class Method:
    token: int

    bytecodes: bytes

    instructions: list

    max_stack: int
    nargs: int
    max_locals: int

    is_extended: bool

    exception_handlers: List[ExceptionHandler] = field(
        default_factory=list
    )

    offset: Optional[int] = None


# =========================================================
# BYTE READERS
# =========================================================

def read_u1(b: bytes, off: int) -> int:
    return b[off]


def read_s1(b: bytes, off: int) -> int:
    val = b[off]
    return val - 0x100 if val & 0x80 else val


def read_u2(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off + 1]


def read_s2(b: bytes, off: int) -> int:
    val = read_u2(b, off)
    return val - 0x10000 if val & 0x8000 else val


def read_u4(b: bytes, off: int) -> int:
    return (
        (b[off] << 24)
        | (b[off + 1] << 16)
        | (b[off + 2] << 8)
        | b[off + 3]
    )


def read_s4(b: bytes, off: int) -> int:
    val = read_u4(b, off)
    return val - 0x100000000 if val & 0x80000000 else val


# =========================================================
# SWITCH PARSERS
# =========================================================

def parse_stableswitch(
    bytecode: bytes,
    offset: int,
) -> tuple[Instruction, int]:

    start = offset
    pos = offset + 1

    # JavaCard:
    # no padding
    # all offsets are s2

    default_rel = read_s2(bytecode, pos)
    pos += 2

    low = read_s2(bytecode, pos)
    pos += 2

    high = read_s2(bytecode, pos)
    pos += 2

    if high < low:
        raise ValueError(
            f"Invalid stableswitch at {start}: "
            f"high < low ({high} < {low})"
        )

    jump_count = high - low + 1

    expected_end = pos + jump_count * 2

    if expected_end > len(bytecode):
        raise ValueError(
            f"Invalid stableswitch at {start}: "
            f"table exceeds bytecode size"
        )

    jumps = []

    for _ in range(jump_count):

        rel = read_s2(bytecode, pos)
        pos += 2

        jumps.append(start + rel)

    instr = Instruction(
        offset=start,
        opcode=bytecode[start],
        mnemonic="stableswitch",
        operands={
            "low": low,
            "high": high,
            "default": start + default_rel,
            "jumps": jumps,
        }
    )

    return instr, pos


def parse_itableswitch(
    bytecode: bytes,
    offset: int,
) -> tuple[Instruction, int]:

    start = offset
    pos = offset + 1

    # JavaCard:
    # default = s2
    # low/high = s4
    # jump offsets = s2

    default_rel = read_s2(bytecode, pos)
    pos += 2

    low = read_s4(bytecode, pos)
    pos += 4

    high = read_s4(bytecode, pos)
    pos += 4

    if high < low:
        raise ValueError(
            f"Invalid itableswitch at {start}: "
            f"high < low ({high} < {low})"
        )

    jump_count = high - low + 1

    expected_end = pos + jump_count * 2

    if expected_end > len(bytecode):
        raise ValueError(
            f"Invalid itableswitch at {start}: "
            f"table exceeds bytecode size"
        )

    jumps = []

    for _ in range(jump_count):

        rel = read_s2(bytecode, pos)
        pos += 2

        jumps.append(start + rel)

    instr = Instruction(
        offset=start,
        opcode=bytecode[start],
        mnemonic="itableswitch",
        operands={
            "low": low,
            "high": high,
            "default": start + default_rel,
            "jumps": jumps,
        }
    )

    return instr, pos


def parse_slookupswitch(bytecode: bytes, offset: int) -> tuple[Instruction, int]:
    """JavaCard slookupswitch: default=s2, npairs=u1, pairs=(match:s2, offset:s2)"""
    start = offset
    pos = offset + 1
    # print(f"DEBUG slookupswitch at {offset}: {bytecode[pos:pos+30].hex()}")
    default_rel = read_s2(bytecode, pos)
    pos += 2

    npairs = read_s2(bytecode, pos)
    pos += 2

    pairs = []
    for _ in range(npairs):
        match = read_s2(bytecode, pos)
        pos += 2
        offset_rel = read_s2(bytecode, pos)
        pos += 2
        pairs.append((match, start + offset_rel))

    instr = Instruction(
        offset=start,
        opcode=bytecode[start],
        mnemonic="slookupswitch",
        operands={
            "default": start + default_rel,
            "npairs": npairs,
            "pairs": pairs,
        }
    )
    return instr, pos


def parse_ilookupswitch(bytecode: bytes, offset: int) -> tuple[Instruction, int]:
    """JavaCard ilookupswitch: default=s2, npairs=u1, pairs=(match:s4, offset:s2)"""
    start = offset
    pos = offset + 1

    default_rel = read_s2(bytecode, pos)
    pos += 2

    npairs = read_u1(bytecode, pos)
    pos += 1

    pairs = []
    for _ in range(npairs):
        match = read_s4(bytecode, pos)
        pos += 4
        offset_rel = read_s2(bytecode, pos)
        pos += 2
        pairs.append((match, start + offset_rel))

    instr = Instruction(
        offset=start,
        opcode=bytecode[start],
        mnemonic="ilookupswitch",
        operands={
            "default": start + default_rel,
            "npairs": npairs,
            "pairs": pairs,
        }
    )
    return instr, pos


# =========================================================
# OPCODE GROUPS
# =========================================================

SIGNED_1 = {
    "bspush",
    "bipush"
}

SIGNED_2 = {
    "sspush",
    "sipush",
}

UNSIGNED_1 = {
    "newarray",
    "sload",
    "sstore",
    "aload",
    "astore",
    "ret",
    "getfield_a_this",
    "getfield_b_this",
    "getfield_s_this",
    "getfield_i_this",
    "putfield_a_this",
    "putfield_b_this",
    "putfield_s_this",
    "putfield_i_this",
    "getfield_a",
    "getfield_b",
    "getfield_s",
    "getfield_i",
    "putfield_a",
    "putfield_b",
    "putfield_s",
    "putfield_i",
}

UNSIGNED_2 = {
    "getfield_a_w",
    "getfield_b_w",
    "getfield_s_w",
    "getfield_i_w",
    "putfield_a_w",
    "putfield_b_w",
    "putfield_s_w",
    "putfield_i_w",
    "invokevirtual",
    "invokespecial",
    "invokestatic",
    "new",
    "anewarray",
}


# =========================================================
# JAVA CARD 3.0.5 OPCODES
# =========================================================
# format:
# opcode: (mnemonic, operand_size)
#
# operand_size:
#   0  -> no operands
#   1  -> 1-byte operand
#   2  -> 2-byte operand
#   4  -> 4-byte operand
#  -1  -> variable length
# =========================================================

OPCODES = {

    # -----------------------------------------------------
    # constants
    # -----------------------------------------------------

    0x00: ("nop", 0),
    0x01: ("aconst_null", 0),

    0x02: ("sconst_m1", 0),
    0x03: ("sconst_0", 0),
    0x04: ("sconst_1", 0),
    0x05: ("sconst_2", 0),
    0x06: ("sconst_3", 0),
    0x07: ("sconst_4", 0),
    0x08: ("sconst_5", 0),

    0x09: ("iconst_m1", 0),
    0x0A: ("iconst_0", 0),
    0x0B: ("iconst_1", 0),
    0x0C: ("iconst_2", 0),
    0x0D: ("iconst_3", 0),
    0x0E: ("iconst_4", 0),
    0x0F: ("iconst_5", 0),

    0x10: ("bspush", 1),
    0x11: ("sspush", 2),
    0x12: ("bipush", 1),
    0x13: ("sipush", 2),
    0x14: ("iipush", 4),

    # -----------------------------------------------------
    # loads
    # -----------------------------------------------------

    0x15: ("aload", 1),
    0x16: ("sload", 1),
    0x17: ("iload", 1),

    0x18: ("aload_0", 0),
    0x19: ("aload_1", 0),
    0x1A: ("aload_2", 0),
    0x1B: ("aload_3", 0),

    0x1C: ("sload_0", 0),
    0x1D: ("sload_1", 0),
    0x1E: ("sload_2", 0),
    0x1F: ("sload_3", 0),

    0x20: ("iload_0", 0),
    0x21: ("iload_1", 0),
    0x22: ("iload_2", 0),
    0x23: ("iload_3", 0),

    # -----------------------------------------------------
    # array loads
    # -----------------------------------------------------

    0x24: ("aaload", 0),
    0x25: ("baload", 0),
    0x26: ("saload", 0),
    0x27: ("iaload", 0),

    # -----------------------------------------------------
    # stores
    # -----------------------------------------------------

    0x28: ("astore", 1),
    0x29: ("sstore", 1),
    0x2A: ("istore", 1),

    0x2B: ("astore_0", 0),
    0x2C: ("astore_1", 0),
    0x2D: ("astore_2", 0),
    0x2E: ("astore_3", 0),

    0x2F: ("sstore_0", 0),
    0x30: ("sstore_1", 0),
    0x31: ("sstore_2", 0),
    0x32: ("sstore_3", 0),

    0x33: ("istore_0", 0),
    0x34: ("istore_1", 0),
    0x35: ("istore_2", 0),
    0x36: ("istore_3", 0),

    # -----------------------------------------------------
    # array stores
    # -----------------------------------------------------

    0x37: ("aastore", 0),
    0x38: ("bastore", 0),
    0x39: ("sastore", 0),
    0x3A: ("iastore", 0),

    # -----------------------------------------------------
    # stack
    # -----------------------------------------------------

    0x3B: ("pop", 0),
    0x3C: ("pop2", 0),
    0x3D: ("dup", 0),
    0x3E: ("dup2", 0),
    0x3F: ("dup_x", 0),
    0x40: ("swap_x", 0),

    # -----------------------------------------------------
    # arithmetic
    # -----------------------------------------------------

    0x41: ("sadd", 0),
    0x42: ("iadd", 0),

    0x43: ("ssub", 0),
    0x44: ("isub", 0),

    0x45: ("smul", 0),
    0x46: ("imul", 0),

    0x47: ("sdiv", 0),
    0x48: ("idiv", 0),

    0x49: ("srem", 0),
    0x4A: ("irem", 0),

    0x4B: ("sneg", 0),
    0x4C: ("ineg", 0),

    0x4D: ("sshl", 0),
    0x4E: ("ishl", 0),

    0x4F: ("sshr", 0),
    0x50: ("ishr", 0),

    0x51: ("sushr", 0),
    0x52: ("iushr", 0),

    0x53: ("sand", 0),
    0x54: ("iand", 0),

    0x55: ("sor", 0),
    0x56: ("ior", 0),

    0x57: ("sxor", 0),
    0x58: ("ixor", 0),

    # -----------------------------------------------------
    # increments
    # -----------------------------------------------------

    0x59: ("sinc", 2),
    0x5A: ("iinc", 2),

    # -----------------------------------------------------
    # conversions
    # -----------------------------------------------------

    0x5B: ("s2b", 0),
    0x5C: ("s2i", 0),
    0x5D: ("i2b", 0),
    0x5E: ("i2s", 0),

    # -----------------------------------------------------
    # compare
    # -----------------------------------------------------

    0x5F: ("icmp", 0),

    # -----------------------------------------------------
    # branches
    # -----------------------------------------------------

    # branches (short)
    0x60: ("ifeq", 1),
    0x61: ("ifne", 1),
    0x62: ("iflt", 1),
    0x63: ("ifge", 1),
    0x64: ("ifgt", 1),
    0x65: ("ifle", 1),
    0x66: ("ifnull", 1),
    0x67: ("ifnonnull", 1),
    0x68: ("if_acmpeq", 1),
    0x69: ("if_acmpne", 1),
    0x6A: ("if_scmpeq", 1),
    0x6B: ("if_scmpne", 1),
    0x6C: ("if_scmplt", 1),
    0x6D: ("if_scmpge", 1),
    0x6E: ("if_scmpgt", 1),
    0x6F: ("if_scmple", 1),
    0x70: ("goto", 1),    # ← было 2
    0x71: ("jsr", 2),     # jsr – двухбайтовый

    0x72: ("ret", 1),

    # -----------------------------------------------------
    # switch
    # -----------------------------------------------------

    0x73: ("stableswitch", -1),
    0x74: ("itableswitch", -1),

    0x75: ("slookupswitch", -1),
    0x76: ("ilookupswitch", -1),

    # -----------------------------------------------------
    # returns
    # -----------------------------------------------------

    0x77: ("areturn", 0),
    0x78: ("sreturn", 0),
    0x79: ("ireturn", 0),
    0x7A: ("return", 0),

    # -----------------------------------------------------
    # static fields
    # -----------------------------------------------------

    0x7B: ("getstatic_a", 2),
    0x7C: ("getstatic_b", 2),
    0x7D: ("getstatic_s", 2),
    0x7E: ("getstatic_i", 2),

    0x7F: ("putstatic_a", 2),
    0x80: ("putstatic_b", 2),
    0x81: ("putstatic_s", 2),
    0x82: ("putstatic_i", 2),

    # -----------------------------------------------------
    # fields
    # -----------------------------------------------------

    0x83: ("getfield_a", 1),
    0x84: ("getfield_b", 1),
    0x85: ("getfield_s", 1),
    0x86: ("getfield_i", 1),

    0x87: ("putfield_a", 1),
    0x88: ("putfield_b", 1),
    0x89: ("putfield_s", 1),
    0x8A: ("putfield_i", 1),

    # -----------------------------------------------------
    # invoke
    # -----------------------------------------------------

    0x8B: ("invokevirtual", 2),
    0x8C: ("invokespecial", 2),
    0x8D: ("invokestatic", 2),
    0x8E: ("invokeinterface", 4),

    # -----------------------------------------------------
    # object/array
    # -----------------------------------------------------

    0x8F: ("new", 2),

    0x90: ("newarray", 1),
    0x91: ("anewarray", 2),

    0x92: ("arraylength", 0),

    0x93: ("athrow", 0),

    0x94: ("checkcast", 3),
    0x95: ("instanceof", 3),

    # -----------------------------------------------------
    # wide increments
    # -----------------------------------------------------

    0x96: ("sinc_w", 4),
    0x97: ("iinc_w", 4),

    # -----------------------------------------------------
    # wide branches
    # NOTE:
    # JavaCard wide branches are STILL s2 offsets
    # -----------------------------------------------------

    0x98: ("ifeq_w", 2),
    0x99: ("ifne_w", 2),
    0x9A: ("iflt_w", 2),
    0x9B: ("ifge_w", 2),
    0x9C: ("ifgt_w", 2),
    0x9D: ("ifle_w", 2),

    0x9E: ("ifnull_w", 2),
    0x9F: ("ifnonnull_w", 2),

    0xA0: ("if_acmpeq_w", 2),
    0xA1: ("if_acmpne_w", 2),

    0xA2: ("if_scmpeq_w", 2),
    0xA3: ("if_scmpne_w", 2),
    0xA4: ("if_scmplt_w", 2),
    0xA5: ("if_scmpge_w", 2),
    0xA6: ("if_scmpgt_w", 2),
    0xA7: ("if_scmple_w", 2),

    0xA8: ("goto_w", 2),

    # -----------------------------------------------------
    # wide fields
    # -----------------------------------------------------

    0xA9: ("getfield_a_w", 2),
    0xAA: ("getfield_b_w", 2),
    0xAB: ("getfield_s_w", 2),
    0xAC: ("getfield_i_w", 2),

    0xAD: ("getfield_a_this", 1),
    0xAE: ("getfield_b_this", 1),
    0xAF: ("getfield_s_this", 1),
    0xB0: ("getfield_i_this", 1),

    0xB1: ("putfield_a_w", 2),
    0xB2: ("putfield_b_w", 2),
    0xB3: ("putfield_s_w", 2),
    0xB4: ("putfield_i_w", 2),

    0xB5: ("putfield_a_this", 1),
    0xB6: ("putfield_b_this", 1),
    0xB7: ("putfield_s_this", 1),
    0xB8: ("putfield_i_this", 1),

    # -----------------------------------------------------
    # implementation dependent
    # -----------------------------------------------------

    0xFE: ("impdep1", 0),
    0xFF: ("impdep2", 0),
}


# =========================================================
# MAIN PARSER
# =========================================================

def parse_bytecode(bytecodes: bytes) -> List[Instruction]:

    instructions = []

    offset = 0
    length = len(bytecodes)

    while offset < length:

        opcode = bytecodes[offset]

        if opcode not in OPCODES:
            raise ValueError(
                f"Unknown opcode 0x{opcode:02X} "
                f"at offset {offset}"
            )

        mnemonic, operand_size = OPCODES[opcode]

        if opcode == 0x73:
            instr, new_offset = parse_stableswitch(
                bytecodes,
                offset,
            )

            instructions.append(instr)
            offset = new_offset
            continue

        if opcode == 0x74:
            instr, new_offset = parse_itableswitch(
                bytecodes,
                offset,
            )

            instructions.append(instr)
            offset = new_offset
            continue
        
        if opcode == 0x75:   # slookupswitch
            instr, new_offset = parse_slookupswitch(bytecodes, offset)
            instructions.append(instr)
            offset = new_offset
            continue

        if opcode == 0x76:   # ilookupswitch
            instr, new_offset = parse_ilookupswitch(bytecodes, offset)
            instructions.append(instr)
            offset = new_offset
            continue

        if offset + 1 + operand_size > length:
            raise ValueError(f"Truncated {mnemonic} at offset {offset}")

        operands = []

        # =================================================
        # signed 16-bit branches
        # =================================================

        # -------------------------------------------------
        # JavaCard 1-byte branches
        # -------------------------------------------------
        if opcode in range(0x60, 0x70 + 1):   # 0x60..0x70 включительно (goto тоже)
            rel = read_s1(bytecodes, offset + 1)
            target = offset + rel
            operands = [target]
            operand_size = 1
        # -------------------------------------------------
        # jsr (2-byte branch)
        # -------------------------------------------------
        elif opcode == 0x71:
            rel = read_s2(bytecodes, offset + 1)
            target = offset + rel
            operands = [target]
            operand_size = 2
        # -------------------------------------------------
        # wide branches (_w) – 2-byte offsets
        # -------------------------------------------------
        elif opcode in range(0x98, 0xA8 + 1):
            rel = read_s2(bytecodes, offset + 1)
            target = offset + rel
            operands = [target]
            operand_size = 2
        # -------------------------------------------------
        # ret
        # -------------------------------------------------
        elif opcode == 0x72:
            operands = [read_u1(bytecodes, offset + 1)]
            operand_size = 1

        # =================================================
        # signed immediate
        # =================================================

        elif mnemonic in SIGNED_1:

            operands = [
                read_s1(bytecodes, offset + 1)
            ]

        elif mnemonic in SIGNED_2:

            operands = [
                read_s2(bytecodes, offset + 1)
            ]

        # =================================================
        # unsigned immediate
        # =================================================

        elif mnemonic in UNSIGNED_1:

            operands = [
                read_u1(bytecodes, offset + 1)
            ]

        elif mnemonic in UNSIGNED_2:

            operands = [
                read_u2(bytecodes, offset + 1)
            ]

        # =================================================
        # sinc
        # =================================================

        elif mnemonic in ("checkcast", "instanceof"):
            operands = [read_u1(bytecodes, offset + 1), read_u2(bytecodes, offset + 2)]

        elif mnemonic == "invokeinterface":
            operands = [read_u1(bytecodes, offset + 1), read_u2(bytecodes, offset + 2),
                        read_u1(bytecodes, offset + 4)]

        elif mnemonic == "sinc":

            index = read_u1(bytecodes, offset + 1)
            const = read_s1(bytecodes, offset + 2)

            operands = [index, const]

        # =================================================
        # no operands
        # =================================================

        elif operand_size == 0:

            operands = []

        # =================================================
        # raw fallback
        # =================================================

        else:

            operands = list(
                bytecodes[
                    offset + 1:
                    offset + 1 + operand_size
                ]
            )

        instructions.append(
            Instruction(
                offset=offset,
                opcode=opcode,
                mnemonic=mnemonic,
                operands=operands,
            )
        )

        offset += 1 + operand_size

    return instructions
