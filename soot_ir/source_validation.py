"""Validate JSON inputs too: defined values, edges, and local-slot data flow."""
from collections import deque

from .input import LoweringError, op_name, stack_kind, terminator_kind


def validate_source(method):
    def fail(message):
        raise LoweringError(f"{method['name']}: {message}")

    blocks = {b["id"]: b for b in method["blocks"]}
    if len(blocks) != len(method["blocks"]) or not blocks or method["entry"] not in blocks:
        fail("Missing entry, duplicate blocks, or empty method")
    if any(type(bid) is not int or bid < 0 for bid in blocks):
        fail("Block ids must be non-negative integers")
    starts = {b["start_offset"] for b in blocks.values()}
    if len(starts) != len(blocks):
        fail("Duplicate source block offsets")
    if blocks[method["entry"]]["parameters"]:
        fail("Method entry stack must be empty")
    nlocals = method["local_slot_count"]
    if type(nlocals) is not int or nlocals < 0:
        fail("Invalid local_slot_count")
    handlers = method["handlers"]
    handler_blocks = {}
    for index, h in enumerate(handlers):
        if not (0 <= h["start"] < h["end"]) or h["target"] not in starts:
            fail("Invalid handler interval or target")
        target = next(b for b in blocks.values() if b["start_offset"] == h["target"])
        if len(target["parameters"]) != 1 or stack_kind(target["parameters"][0]["type"]) != "reference":
            fail("Handler needs a single reference parameter")
        handler_blocks[index] = target["id"]

    def annotations(operation):
        indices = operation.get("handler_indices", [])
        if list(indices) != sorted(set(indices)):
            fail("Handler annotations must preserve table order, without duplicates")
        for index in indices:
            if type(index) is not int or not 0 <= index < len(handlers):
                fail("Unknown handler index")
            h = handlers[index]
            if not h["start"] <= operation["offset"] < h["end"]:
                fail("Handler annotation outside protected interval")
        throws = operation.get("may_throw", False) or ("kind" in operation and terminator_kind(operation) == "throw")
        if throws:
            expected = [i for i, h in enumerate(handlers) if h["start"] <= operation["offset"] < h["end"]]
            if list(indices) != expected:
                fail("Throwing operation is missing an applicable handler annotation")

    def operand_kind(operand, defined):
        result = stack_kind(operand["type"])
        if result == "void":
            fail("Void operand")
        if "name" in operand:
            if defined.get(operand["name"]) != result:
                fail(f"Undefined, mistyped or cross-block value: {operand['name']}")
        elif "value" not in operand:
            fail("Operand needs name or value")
        return result

    normal = {bid: [] for bid in blocks}
    exceptional = set()
    for edge in method["edges"]:
        if edge["source"] not in blocks or edge["target"] not in blocks:
            fail("Dangling edge")
        if edge["kind"] == "EXCEPTION":
            index = edge.get("handler_index")
            if index not in handler_blocks or handler_blocks[index] != edge["target"] or edge.get("arguments"):
                fail("Malformed exceptional edge")
            exceptional.add((edge["source"], index))
        else:
            normal[edge["source"]].append(edge)
    for bid, block in blocks.items():
        defined = {}
        for param in block["parameters"]:
            if param["name"] in defined:
                fail("Duplicate block parameter")
            defined[param["name"]] = stack_kind(param["type"])
        statement_ids = set()
        for stmt in block["statements"]:
            if stmt["id"] in statement_ids:
                fail("Duplicate statement id within block")
            statement_ids.add(stmt["id"])
            for operand in stmt.get("operands", []):
                operand_kind(operand, defined)
            op = op_name(stmt)
            requires_throw_flag = op in ("load_field", "store_field", "array_load", "array_store", "array_length", "new_object", "new_array", "call", "div", "rem") or (op == "binary" and stmt.get("mode") in ("div", "rem"))
            if requires_throw_flag and not stmt.get("may_throw", False):
                fail(f"{op} must be marked may_throw; exception semantics cannot be dropped")
            annotations(stmt)
            if stmt.get("may_throw"):
                for index in stmt.get("handler_indices", []):
                    if (bid, index) not in exceptional:
                        fail("Missing exception edge for throwing statement")
            result = stmt.get("result")
            if result is not None:
                if result["name"] in defined:
                    fail("A value is defined twice")
                defined[result["name"]] = stack_kind(result["type"])
        term = block["terminator"]
        for operand in term.get("operands", []):
            operand_kind(operand, defined)
        annotations(term)
        if terminator_kind(term) == "throw":
            for index in term.get("handler_indices", []):
                if (bid, index) not in exceptional:
                    fail("Missing exception edge for throw")
        for edge in normal[bid]:
            arguments, parameters = edge.get("arguments", []), blocks[edge["target"]]["parameters"]
            if len(arguments) != len(parameters):
                fail("Edge argument count mismatch")
            for arg, param in zip(arguments, parameters):
                if operand_kind(arg, defined) != stack_kind(param["type"]):
                    fail("Edge argument type mismatch")

    # Definite initialization over the original control flow. int occupies two
    # JCVM slots even though its Soot local is one 32-bit value.
    initial = [None] * nlocals
    receivers = [a for a in method["arguments"] if a["is_receiver"]]
    if len(receivers) > 1 or receivers and (receivers[0]["slot"] != 0 or method["arguments"][0] != receivers[0]):
        fail("Invalid receiver placement")
    expected_args = method["signature"]["parameters"]
    actual_args = [a["declared_type"] for a in method["arguments"] if not a["is_receiver"]]
    if actual_args != expected_args:
        fail("Arguments disagree with signature")
    next_slot = 0
    for argument in method["arguments"]:
        sk = stack_kind(argument["declared_type"])
        width = 2 if sk == "int" else 1
        slot = argument["slot"]
        if slot != next_slot or slot + width > nlocals or sk == "void" or argument["is_receiver"] and sk != "reference":
            fail("Invalid argument slot layout")
        initial[slot] = sk
        if width == 2:
            initial[slot + 1] = "tail"
        next_slot += width

    def overwrite(state, slot, sk):
        width = 2 if sk == "int" else 1
        if type(slot) is not int or slot < 0 or slot + width > nlocals:
            fail(f"Local slot {slot} out of bounds")
        for index in range(slot, slot + width):
            if state[index] == "tail" and index:
                state[index - 1] = None
            if state[index] == "int" and index + 1 < nlocals:
                state[index + 1] = None
            state[index] = None
        state[slot] = sk
        if width == 2:
            state[slot + 1] = "tail"

    entries = {method["entry"]: tuple(initial)}
    queue = deque([method["entry"]])

    def propagate(target, state):
        state = tuple(state)
        if target in entries:
            state = tuple(a if a == b else None for a, b in zip(entries[target], state))
        if entries.get(target) != state:
            entries[target] = state
            queue.append(target)

    while queue:
        bid = queue.popleft()
        state = list(entries[bid])
        block = blocks[bid]
        for stmt in block["statements"]:
            if stmt.get("may_throw"):
                for index in stmt.get("handler_indices", []):
                    propagate(handler_blocks[index], state)
            op = op_name(stmt)
            if op == "load_local":
                index, sk = stmt["local_index"], stack_kind(stmt["result"]["type"])
                if type(index) is not int or not 0 <= index < nlocals or state[index] != sk or (sk == "int" and (index + 1 >= nlocals or state[index + 1] != "tail")):
                    fail(f"B{bid} @{stmt['offset']}: uninitialized or mistyped local {index}")
            elif op == "store_local":
                sk = stack_kind(stmt["semantic_type"])
                if len(stmt["operands"]) != 1 or stack_kind(stmt["operands"][0]["type"]) != sk:
                    fail("Local store type mismatch")
                overwrite(state, stmt["local_index"], sk)
        if terminator_kind(block["terminator"]) == "throw":
            for index in block["terminator"].get("handler_indices", []):
                propagate(handler_blocks[index], state)
        for edge in normal[bid]:
            propagate(edge["target"], state)
