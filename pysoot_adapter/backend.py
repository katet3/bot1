"""Lazy imports and an explicit contract for real pysoot dataclasses."""
from __future__ import annotations

from dataclasses import fields, is_dataclass
from functools import lru_cache
from importlib import import_module, metadata
from types import SimpleNamespace

from .errors import DependencyError


PYSOOT_REVISION = "16ab55db71a162efea3d44251fb93893140bbef2"
INSTALL_HINT = "python -m pip install -r requirements-pysoot.txt"

# Includes inherited fields, in constructor order.
CONTRACT = {
    "soot_value": {
        "SootLocal": "type name", "SootIntConstant": "type value", "SootNullConstant": "type",
        "SootThisRef": "type", "SootParamRef": "type index", "SootCaughtExceptionRef": "type",
        "SootArrayRef": "type base index", "SootInstanceFieldRef": "type base field",
        "SootStaticFieldRef": "type field",
    },
    "soot_expr": {
        "SootBinopExpr": "type op value1 value2", "SootUnopExpr": "type op value",
        "SootCastExpr": "type cast_type value", "SootConditionExpr": "type op value1 value2",
        "SootLengthExpr": "type value", "SootNewExpr": "type base_type",
        "SootNewArrayExpr": "type base_type size",
        "SootStaticInvokeExpr": "type class_name method_name method_params args",
        "SootVirtualInvokeExpr": "type class_name method_name method_params args base",
        "SootSpecialInvokeExpr": "type class_name method_name method_params args base",
        "SootInterfaceInvokeExpr": "type class_name method_name method_params args base",
    },
    "soot_statement": {
        "AssignStmt": "label offset left_op right_op", "IdentityStmt": "label offset left_op right_op",
        "GotoStmt": "label offset target", "IfStmt": "label offset condition target",
        "InvokeStmt": "label offset invoke_expr", "ReturnStmt": "label offset value",
        "ReturnVoidStmt": "label offset", "ThrowStmt": "label offset obj",
        "LookupSwitchStmt": "label offset key lookup_values_and_targets default_target",
    },
    "soot_block": {"SootBlock": "label statements idx"},
    "soot_method": {"SootMethod": "class_name name ret attrs exceptions blocks params basic_cfg exceptional_preds"},
    "soot_class": {"SootClass": "name super_class interfaces attrs methods fields"},
}


@lru_cache(maxsize=1)
def load_backend():
    """Import the object model only; never instantiate Lifter or start a JVM."""
    objects = {}
    try:
        for module_name, expected in CONTRACT.items():
            module = import_module(f"pysoot.sootir.{module_name}")
            for name, names in expected.items():
                cls = getattr(module, name, None)
                if not is_dataclass(cls) or [f.name for f in fields(cls)] != names.split():
                    raise DependencyError(
                        f"Incompatible pysoot class {name}; expected revision {PYSOOT_REVISION}. {INSTALL_HINT}"
                    )
                objects[name] = cls
        objects["frozendict"] = import_module("frozendict").frozendict
    except ImportError as exc:
        raise DependencyError(f"pysoot dependency unavailable ({exc}). {INSTALL_HINT}") from exc
    try:
        version = metadata.version("pysoot")
    except metadata.PackageNotFoundError:
        version = "source-checkout"
    return SimpleNamespace(**objects, version=version, target_revision=PYSOOT_REVISION)
