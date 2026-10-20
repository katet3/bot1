"""CAP identities stay stable across constant-pool reindexing.

Human-readable external names are supplied explicitly, never inferred from CP numbers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from .input import LoweringError, kind
from .model import FieldRef, MethodRef


def package_key(aid, version):
    if not isinstance(aid, str) or not re.fullmatch(r"[0-9a-fA-F]+", aid) or len(aid) % 2:
        raise LoweringError(f"Invalid package AID: {aid!r}")
    if len(version) != 2 or any(type(v) is not int or not 0 <= v <= 255 for v in version):
        raise LoweringError(f"Invalid package version: {version!r}")
    return f"{aid.lower()}@{version[0]}.{version[1]}"


def reference_key(ref):
    package = package_key(ref["package_aid"], ref["package_version"])
    if not ref["external"] and ref.get("internal_offset") is not None:
        return f"{package}:internal:t{ref['tag']}:o{ref['internal_offset']}"
    class_id = "c" + str(ref["class_token"]) if ref["external"] else "o" + str(ref["class_offset"])
    key = f"{package}:{class_id}:t{ref['tag']}"
    if ref.get("member_token") is not None:
        key += f":m{ref['member_token']}"
    return key


@dataclass
class SymbolTable:
    package_aid: str
    package_version: tuple[int, int]
    imports: tuple[tuple[str, tuple[int, int]], ...] = ()
    class_names: dict[str, str] = field(default_factory=dict)
    method_names: dict[str, str] = field(default_factory=dict)
    field_names: dict[str, str] = field(default_factory=dict)
    catch_types: dict[int, str] = field(default_factory=dict)

    def __post_init__(self):
        self.package = package_key(self.package_aid, self.package_version)
        self.package_aid = self.package_aid.lower()
        self.unresolved = set()
        self.methods = {}
        self._by_offset = {}
        self._members = {}

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["package_aid"], tuple(data["package_version"]),
            tuple((i["aid"], tuple(i["version"])) for i in data.get("imports", [])),
            dict(data.get("class_names", {})), dict(data.get("method_names", {})),
            dict(data.get("field_names", {})),
            {int(k): v for k, v in data.get("catch_types", {}).items()},
        )

    def class_name(self, aid, version, class_id, external):
        if type(class_id) is not int or class_id < 0:
            raise LoweringError("Class identity is missing; cannot guess an owner")
        pkg = package_key(aid, version)
        key = f"{pkg}:{'c' if external else 'o'}{class_id}"
        if key in self.class_names:
            return self.class_names[key]
        if external:
            self.unresolved.add(key)
        return f"cap.p{aid.lower()}.v{version[0]}_{version[1]}.{'C' if external else 'Class'}{class_id}"

    def reference_class(self, ref):
        return self.class_name(ref["package_aid"], ref["package_version"],
                               ref["class_token"] if ref["external"] else ref["class_offset"], ref["external"])

    def type_name(self, type_):
        k = kind(type_)
        if k in ("void", "boolean", "byte", "short", "int") or k in ("boolean[]", "byte[]", "short[]", "int[]"):
            return k
        if k not in ("reference", "reference[]"):
            raise LoweringError(f"Unsupported declared type {k!r}")
        class_ref = type_.get("class_ref") if isinstance(type_, dict) else None
        if class_ref is None:
            base = "java.lang.Object"
        elif class_ref & 0x8000:
            package_index = (class_ref >> 8) & 0x7f
            if package_index >= len(self.imports):
                raise LoweringError(f"Import #{package_index} required to resolve class_ref={class_ref}")
            aid, version = self.imports[package_index]
            base = self.class_name(aid, version, class_ref & 0xff, True)
        else:
            base = self.class_name(self.package_aid, self.package_version, class_ref, False)
        return base + ("[]" if k.endswith("[]") else "")

    def register(self, method):
        match = re.fullmatch(r"([0-9a-fA-F]+)/class_(\d+)/method_(\d+)", method["name"])
        if not match or match[1].lower() != self.package_aid:
            raise LoweringError("Method name must be <package_aid>/class_<offset>/method_<offset>")
        class_offset, method_offset = int(match[2]), int(match[3])
        key = f"{self.package}:internal:t6:o{method_offset}"
        owner = self.class_name(self.package_aid, self.package_version, class_offset, False)
        name = self.method_names.get(key, f"method_{method_offset}")
        sig = method["signature"]
        symbol = MethodRef(key, owner, name, tuple(self.type_name(t) for t in sig["parameters"]),
                           self.type_name(sig["returns"]), not any(a["is_receiver"] for a in method["arguments"]))
        if key in self.methods:
            raise LoweringError(f"Duplicate method identity {key}")
        if (owner, name, symbol.params) in self._members:
            raise LoweringError(f"Duplicate Soot method signature: {symbol.signature}")
        self._members[(owner, name, symbol.params)] = key
        self.methods[key] = symbol
        self._by_offset[method_offset] = symbol
        return symbol

    def method_ref(self, ref, mode):
        key = reference_key(ref)
        is_static = mode == "static"
        if not ref["external"] and ref.get("internal_offset") is not None:
            if key not in self.methods:
                raise LoweringError(f"Internal callee {key} is missing. Use build_program() with all methods.")
            result = self.methods[key]
            if result.is_static != is_static:
                raise LoweringError(f"Call mode disagrees with {result.signature}")
            signature = ref.get("signature")
            if signature is None or (tuple(self.type_name(t) for t in signature["parameters"]), self.type_name(signature["returns"])) != (result.params, result.returns):
                raise LoweringError(f"Call signature disagrees with {result.signature}")
            return result
        signature = ref.get("signature")
        if signature is None:
            raise LoweringError(f"Missing method signature: {key}")
        owner = self.reference_class(ref)
        name = self.method_names.get(key)
        if name is None:
            self.unresolved.add(key)
            name = f"method_t{ref['tag']}_{ref['member_token']}"
        return MethodRef(key, owner, name, tuple(self.type_name(t) for t in signature["parameters"]),
                         self.type_name(signature["returns"]), is_static, key in self.method_names)

    def field_ref(self, ref, mode):
        key = reference_key(ref)
        if ref.get("field_type") is None:
            raise LoweringError(f"Missing field type: {key}")
        if ref.get("class_offset") is None and not ref["external"]:
            raise LoweringError("Internal static field needs a declaring class binding; offset alone is insufficient")
        owner = self.reference_class(ref)
        name = self.field_names.get(key, f"field_t{ref['tag']}_{ref['member_token']}")
        if ref["external"] and key not in self.field_names:
            self.unresolved.add(key)
        return FieldRef(key, owner, name, self.type_name(ref["field_type"]), mode == "static",
                        not ref["external"] or key in self.field_names)

    def catch_type(self, index):
        if index == 0:
            return "java.lang.Throwable"
        if index not in self.catch_types:
            raise LoweringError(f"catch_types[{index}] must resolve the handler's constant-pool class reference")
        return self.catch_types[index]
