"""CAP keys / byte offsets <-> Soot descriptors / block and statement indices."""
from dataclasses import asdict, dataclass

from .errors import LoaderError


@dataclass(frozen=True)
class SourceLocation:
    method_key: str
    block_index: int
    statement_index: int
    unit_label: int
    cap_offset: int | None
    source_block: int | None
    source_statement: str | None
    handlers: tuple[int, ...]

    def to_dict(self):
        return asdict(self)


class MethodIndex:
    def __init__(self, program, arch):
        self.program = program
        self.arch = arch
        self.descriptors = {}
        self.by_signature = {}
        self.locations = {}
        self.by_label = {}
        self.by_offset = {}
        for key, method in program.methods.items():
            signature = (method.class_name, method.name, tuple(method.params))
            if signature in self.by_signature:
                raise LoaderError(f"angr cannot distinguish duplicate method signature: {signature}")
            self.by_signature[signature] = key
            self.descriptors[key] = arch.SootMethodDescriptor.from_soot_method(method)
            cls = program.classes.get(method.class_name)
            if cls is None or method not in cls.methods:
                raise LoaderError(f"Method {key} is not declared in class {method.class_name}")
            origins = {row[0]: row[1:] for row in program.details[key].unit_origins}
            seen = set()
            for block_index, block in enumerate(method.blocks):
                if block.idx != block_index or not block.statements or block.label != block.statements[0].label:
                    raise LoaderError(f"Invalid block numbering or empty block in {key}")
                for stmt_index, stmt in enumerate(block.statements):
                    if stmt.label in seen or stmt.label not in origins:
                        raise LoaderError(f"Duplicate label or missing source location: {key}, label {stmt.label}")
                    seen.add(stmt.label)
                    offset, source_block, source_stmt, handlers = origins[stmt.label]
                    location = SourceLocation(key, block_index, stmt_index, stmt.label,
                                              offset, source_block, source_stmt, handlers)
                    self.locations[key, block_index, stmt_index] = location
                    self.by_label[key, stmt.label] = location
                    if offset is not None:
                        self.by_offset.setdefault((key, offset), []).append(location)
            for block in method.blocks:
                for stmt in block.statements:
                    targets = []
                    if type(stmt).__name__ in {"IfStmt", "GotoStmt"}:
                        targets.append(stmt.target)
                    elif type(stmt).__name__ == "LookupSwitchStmt":
                        targets.extend(stmt.lookup_values_and_targets.values())
                        targets.append(stmt.default_target)
                    if any(target not in method.block_by_label for target in targets):
                        raise LoaderError(f"Jump target is not a block label in {key}")

    def method(self, key):
        try:
            return self.program.methods[key]
        except KeyError as exc:
            raise LoaderError(f"Unknown CAP method key: {key}") from exc

    def key_for_descriptor(self, descriptor):
        signature = (descriptor.class_name, descriptor.name, tuple(descriptor.params))
        try:
            return self.by_signature[signature]
        except KeyError as exc:
            raise LoaderError(f"Method is not loaded: {descriptor}") from exc

    def entry(self, key):
        method = self.method(key)
        if not method.blocks or {"ABSTRACT", "NATIVE"}.intersection(method.attrs):
            raise LoaderError(f"Method has no executable body: {key}")
        return self.arch.SootAddressDescriptor(self.descriptors[key], 0, 0)

    def address(self, location):
        return self.arch.SootAddressDescriptor(self.descriptors[location.method_key],
                                               location.block_index, location.statement_index)

    def at_label(self, key, label):
        self.method(key)
        try:
            return self.address(self.by_label[key, label])
        except KeyError as exc:
            raise LoaderError(f"No Unit label {label} in {key}") from exc

    def at_offset(self, key, offset):
        self.method(key)
        return tuple(self.address(loc) for loc in self.by_offset.get((key, offset), ()))

    def source(self, address):
        if not isinstance(address, self.arch.SootAddressDescriptor) or isinstance(address, self.arch.SootAddressTerminator):
            raise LoaderError(f"Not a method instruction address: {address}")
        key = self.key_for_descriptor(address.method)
        try:
            return self.locations[key, address.block_idx, address.stmt_idx]
        except KeyError as exc:
            raise LoaderError(f"Invalid Soot instruction address: {address}") from exc

