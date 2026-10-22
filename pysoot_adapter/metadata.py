"""Declarations missing from method bodies; independent of the CAP parser."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FieldMetadata:
    key: str
    name: str
    type: str
    attrs: tuple[str, ...] = ()
    token: int | None = None
    offset: int | None = None


@dataclass(frozen=True)
class MethodMetadata:
    key: str
    name: str
    params: tuple[str, ...]
    returns: str
    attrs: tuple[str, ...] = ()
    token: int | None = None
    offset: int | None = None
    aliases: tuple[str, ...] = ()
    # Declared throws types are distinct from exception handler tables.
    exceptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClassMetadata:
    name: str
    super_class: str
    interfaces: tuple[str, ...] = ()
    attrs: tuple[str, ...] = ()
    fields: tuple[FieldMetadata, ...] = ()
    methods: tuple[MethodMetadata, ...] = ()
    token: int | None = None
    offset: int | None = None


@dataclass(frozen=True)
class AppletMetadata:
    aid: str
    install_method_key: str


@dataclass(frozen=True)
class ProgramMetadata:
    classes: tuple[ClassMetadata, ...]
    applets: tuple[AppletMetadata, ...] = ()
    unresolved_symbols: tuple[str, ...] = ()
