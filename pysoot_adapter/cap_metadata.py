"""Read declarations from the parsed CAP; do not guess names from CP indices."""
from __future__ import annotations

from dataclasses import asdict, replace

from jcvm_ir.resolver import DescriptorTypes
from soot_ir import SymbolTable

from .errors import AdapterError
from .metadata import AppletMetadata, ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata


CLASS_FLAGS = {0x01: "PUBLIC", 0x10: "FINAL", 0x40: "INTERFACE", 0x80: "ABSTRACT"}
FIELD_FLAGS = {0x01: "PUBLIC", 0x02: "PRIVATE", 0x04: "PROTECTED", 0x08: "STATIC", 0x10: "FINAL"}
METHOD_FLAGS = {**FIELD_FLAGS, 0x40: "ABSTRACT", 0x80: "CONSTRUCTOR"}


def _attrs(flags, mapping):
    if flags & ~sum(mapping):
        raise AdapterError(f"Unsupported CAP access flags: {flags:#x}")
    return tuple(name for bit, name in mapping.items() if flags & bit)


def metadata_from_cap(cap_file, symbols: SymbolTable) -> ProgramMetadata:
    """Join Class and Descriptor by info-relative offsets, not by list position.

    CAP descriptor flags differ from JVM flags (notably ABSTRACT/INTERFACE).
    External class hierarchies are not present in a CAP and are not fabricated.
    """
    symbols = replace(symbols)
    package = cap_file.header.package
    version = (package.major_version, package.minor_version)
    imports = tuple((p.aid.hex(), (p.major_version, p.minor_version))
                    for p in cap_file.import_componet.packages)
    if (package.aid.hex(), version) != (symbols.package_aid, symbols.package_version):
        raise AdapterError("Symbol configuration package/version differs from CAP")
    configured_imports = tuple((aid.lower(), tuple(v)) for aid, v in symbols.imports)
    if configured_imports != imports:
        raise AdapterError("Symbol configuration imports differ from CAP (including order)")
    types = DescriptorTypes(cap_file.descriptor)
    declarations = {}
    for info in (*cap_file.class_component.classes, *cap_file.class_component.interfaces):
        offset = getattr(info, "offset", None)
        if offset is None:
            raise AdapterError("Class.cap offsets are missing; update class_component.py")
        if offset in declarations:
            raise AdapterError(f"Duplicate Class.cap declaration offset {offset}")
        declarations[offset] = info

    def class_name(ref):
        if type(ref) is not int or not 0 <= ref <= 0xFFFF:
            raise AdapterError(f"Invalid class reference {ref}")
        if not ref & 0x8000 and ref not in declarations:
            raise AdapterError(f"Missing internal class at offset {ref}")
        return symbols.type_name({"kind": "reference", "class_ref": ref})

    def class_ref(ref):
        if ref.is_external:
            if ref.package_token is None or not 0 <= ref.package_token < len(imports):
                raise AdapterError("Invalid package token in Class.cap")
            return class_name(0x8000 | (ref.package_token << 8) | ref.class_token)
        return "" if ref.internal_offset == 0xFFFF else class_name(ref.internal_offset)

    classes = []
    seen = set()
    for descriptor in cap_file.descriptor.classes:
        offset = descriptor.this_class_ref
        if offset in seen or offset not in declarations:
            raise AdapterError(f"Cannot uniquely join Descriptor class at offset {offset}")
        seen.add(offset)
        info = declarations[offset]
        attrs = _attrs(descriptor.access_flags, CLASS_FLAGS)
        is_interface = "INTERFACE" in attrs
        if is_interface != bool(info.flags & 0x8):
            raise AdapterError(f"Class/interface flag disagreement at offset {offset}")
        owner = class_name(offset)
        if is_interface:
            parent = "java.lang.Object"
            interfaces = tuple(class_ref(ref) for ref in info.superinterfaces)
        else:
            parent = class_ref(info.super_class_ref)
            interfaces = tuple(class_name(ref) for ref in descriptor.interfaces)
            runtime_interfaces = tuple(class_ref(item.interface) for item in info.interfaces)
            if set(runtime_interfaces) != set(interfaces):
                raise AdapterError(f"Interface lists disagree for {owner}")

        fields = []
        for field in descriptor.fields:
            field_attrs = _attrs(field.access_flags, FIELD_FLAGS)
            if field.is_static != ("STATIC" in field_attrs):
                raise AdapterError(f"Static flag disagreement in {owner}")
            static_offset = None
            if field.is_static:
                # The existing parser retains static_field_ref's three bytes
                # in class_ref (pad + high byte) and token (low byte).
                static_offset = ((field.field_ref.class_ref & 0xFF) << 8) | field.field_ref.token
                key = f"{symbols.package}:internal:t5:o{static_offset}"
                default_name = f"field_static_{static_offset}"
            else:
                if field.field_ref.class_ref != offset:
                    raise AdapterError(f"Instance field owner disagrees with {owner}")
                key = f"{symbols.package}:o{offset}:t2:m{field.field_ref.token}"
                default_name = f"field_t2_{field.field_ref.token}"
            if field.is_primitive:
                type_name = {2: "boolean", 3: "byte", 4: "short", 5: "int"}.get(field.type_value & 0x7FFF)
                if type_name is None:
                    raise AdapterError(f"Invalid primitive field type {field.type_value:#x}")
            else:
                field_types = types.get(field.type_value)
                if len(field_types) != 1 or field_types[0].kind == "void":
                    raise AdapterError(f"Invalid type descriptor for {key}")
                type_name = symbols.type_name(asdict(field_types[0]))
            fields.append(FieldMetadata(key, symbols.field_names.get(key, default_name),
                                        type_name, field_attrs, field.token, static_offset))

        methods = []
        for method in descriptor.methods:
            method_attrs = _attrs(method.access_flags, METHOD_FLAGS)
            if is_interface:
                key = f"{symbols.package}:o{offset}:t3:m{method.token}"
                default_name = f"method_t3_{method.token}"
            else:
                key = f"{symbols.package}:internal:t6:o{method.method_offset}"
                default_name = f"method_{method.method_offset}"
            name = symbols.method_names.get(key, default_name)
            if "CONSTRUCTOR" in method_attrs:
                name = "<init>"
            signature = types.signature(method.type_offset)
            params = tuple(symbols.type_name(asdict(t)) for t in signature.parameters)
            returns = symbols.type_name(asdict(signature.returns))
            aliases = ()
            if not {"STATIC", "CONSTRUCTOR", "PRIVATE"}.intersection(method_attrs):
                # A package virtual token can legitimately be 255.
                aliases = tuple(f"{symbols.package}:o{offset}:t{tag}:m{method.token}" for tag in (3, 4))
            methods.append(MethodMetadata(key, name, params, returns, method_attrs,
                                          method.token, None if is_interface else method.method_offset, aliases))
        classes.append(ClassMetadata(owner, parent, interfaces, attrs, tuple(fields),
                                     tuple(methods), descriptor.token, offset))
    if seen != set(declarations):
        raise AdapterError("Class.cap declarations are missing from Descriptor.cap")
    applets = tuple(AppletMetadata(a.aid.hex(), f"{symbols.package}:internal:t6:o{a.install_method_offset}")
                    for a in cap_file.applet.applets)
    return ProgramMetadata(tuple(classes), applets, tuple(sorted(symbols.unresolved)))
