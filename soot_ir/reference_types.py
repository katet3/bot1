"""Conservative reference typing for immutable values and reusable local slots."""
from .input import op_name, stack_kind


def infer_reference_types(source, symbols, owner):
    values, slots = {}, {}

    def join(old, new):
        if old is None:
            return new
        if new is None or old == new:
            return old
        return "java.lang.Object"

    def operand_type(block, operand):
        return values.get((block, operand["name"])) if "name" in operand else None

    def put(table, key, value):
        merged = join(table.get(key), value)
        if merged is not None and table.get(key) != merged:
            table[key] = merged
            return True
        return False

    for argument in source["arguments"]:
        if stack_kind(argument["declared_type"]) == "reference":
            slots[argument["slot"]] = owner if argument["is_receiver"] else symbols.type_name(argument["declared_type"])
    for handler in source["handlers"]:
        for block in source["blocks"]:
            if block["start_offset"] == handler["target"]:
                put(values, (block["id"], block["parameters"][0]["name"]), symbols.catch_type(handler["catch_type_index"]))
    changed = True
    while changed:
        changed = False
        for block in source["blocks"]:
            bid = block["id"]
            for stmt in block["statements"]:
                op, result = op_name(stmt), stmt.get("result")
                if op == "store_local" and stack_kind(stmt["semantic_type"]) == "reference":
                    changed |= put(slots, stmt["local_index"], operand_type(bid, stmt["operands"][0]))
                if result is None or stack_kind(result["type"]) != "reference":
                    continue
                type_ = None
                if op == "load_local":
                    type_ = slots.get(stmt["local_index"])
                elif op == "new_object":
                    type_ = symbols.reference_class(stmt["reference"])
                elif op in ("new_array", "array_load"):
                    type_ = symbols.type_name(stmt["semantic_type"])
                elif op == "load_field":
                    type_ = symbols.type_name(stmt["reference"]["field_type"])
                elif op == "call":
                    type_ = symbols.type_name(stmt["reference"]["signature"]["returns"])
                elif op in ("copy", "const"):
                    type_ = operand_type(bid, stmt["operands"][0])
                changed |= put(values, (bid, result["name"]), type_)
        blocks = {b["id"]: b for b in source["blocks"]}
        for edge in source["edges"]:
            if edge["kind"] == "EXCEPTION":
                continue
            for arg, param in zip(edge.get("arguments", ()), blocks[edge["target"]]["parameters"]):
                if stack_kind(param["type"]) == "reference":
                    changed |= put(values, (edge["target"], param["name"]), operand_type(edge["source"], arg))
    return slots, values
