"""Type and declaration checks shared by readiness and the execution heap."""
from .errors import HeapError


PRIMITIVES = {"byte": 8, "short": 16, "int": 32, "boolean": 1}
_UNSUPPORTED = {"void", "char", "long", "float", "double"}


def is_reference_type(type_):
    if not isinstance(type_, str) or not type_:
        return False
    if type_.endswith("[]"):
        return is_value_type(type_[:-2])
    return type_ not in {*PRIMITIVES, *_UNSUPPORTED}


def is_value_type(type_):
    return type_ in PRIMITIVES or is_reference_type(type_)


class HeapSchema:
    """Only declarations actually supplied by CAP/metadata are trusted."""

    def __init__(self, program, extra_classes=()):
        self.classes = {c.name: c for c in program.metadata.classes}
        for cls in extra_classes:
            if cls.name in self.classes:
                raise HeapError('class_hierarchy', f'API declaration conflicts with CAP: {cls.name}')
            self.classes[cls.name] = cls

    def lineage(self, type_):
        result, seen = [], set()
        while type_ and type_ != "java.lang.Object":
            if type_ in seen:
                raise HeapError("class_hierarchy", f"Cycle in class hierarchy at {type_}")
            seen.add(type_)
            cls = self.classes.get(type_)
            if cls is None:
                raise HeapError("class_hierarchy", f"Missing class declaration: {type_}")
            result.append(cls)
            type_ = cls.super_class
        return tuple(result)

    def allocation_fields(self, type_):
        if type_ not in self.classes:
            raise HeapError("class_hierarchy", f"Cannot allocate undeclared class {type_}")
        if {"INTERFACE", "ABSTRACT"}.intersection(self.classes[type_].attrs):
            raise HeapError("allocation_type", f"Cannot instantiate {type_}")
        result = []
        for cls in self.lineage(type_):
            if any(m.name == "<clinit>" for m in cls.methods):
                raise HeapError("class_initialization", f"Initializer of {cls.name} is not modeled")
            for field in cls.fields:
                if "STATIC" not in field.attrs:
                    if not is_value_type(field.type):
                        raise HeapError("field_type", f"Unsupported field type {field.type}")
                    result.append((cls.name, field))
        return tuple(result)

    def field(self, owner, name, type_):
        cls = self.classes.get(owner)
        field = next((f for f in cls.fields if f.name == name), None) if cls else None
        if field is None or field.type != type_ or "STATIC" in field.attrs:
            raise HeapError("field_declaration", f"Missing instance field: {owner}.{name}<{type_}>")
        return field

    def assignable(self, actual, expected):
        if actual == expected:
            return True
        if not is_reference_type(actual) or not is_reference_type(expected):
            return False
        if expected == "java.lang.Object":
            return True
        if actual.endswith("[]"):
            if not expected.endswith("[]"):
                return False
            a, b = actual[:-2], expected[:-2]
            if a in PRIMITIVES or b in PRIMITIVES:
                return a == b
            return self.assignable(a, b)
        if expected.endswith("[]"):
            return False
        # Interface declarations are followed too; an unknown ancestor is not
        # evidence of an incompatible type.
        todo, seen, unknown = [actual], set(), set()
        while todo:
            current = todo.pop()
            if current == expected:
                return True
            if current in seen or current == "java.lang.Object":
                continue
            seen.add(current)
            cls = self.classes.get(current)
            if cls is None:
                unknown.add(current)
                continue
            todo.extend(t for t in (cls.super_class, *cls.interfaces) if t)
        if unknown:
            raise HeapError("class_hierarchy", "Incomplete hierarchy: " + ", ".join(sorted(unknown)))
        return False
