"""Public loader facade and deterministic diagnostics."""
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from pysoot_adapter import AdaptedProgram

from .dependencies import VERSIONS, load_dependencies
from .errors import LoaderError
from .index import MethodIndex
from .readiness import ExecutionReadiness, SUPPORTED_FEATURES
from .state import create_call_state


@dataclass(frozen=True)
class LoadedProgram:
    program: AdaptedProgram
    project: object
    index: MethodIndex
    readiness: ExecutionReadiness
    entry_key: str | None
    dependencies: object

    def method_address(self, method_key):
        return self.index.entry(method_key)

    def address_for_label(self, method_key, label):
        return self.index.at_label(method_key, label)

    def addresses_for_offset(self, method_key, cap_offset):
        return self.index.at_offset(method_key, cap_offset)

    def source_location(self, address):
        return self.index.source(address)

    def create_call_state(self, method_key=None, args=(), *, receiver=None, base_state=None):
        key = method_key if method_key is not None else self.entry_key
        if key is None:
            raise LoaderError("No unique entry point; pass a CAP method key")
        return create_call_state(self, key, args, receiver=receiver, base_state=base_state)

    def create_heap_state(self, method_key=None):
        """Empty heap and frames for explicit preparation; does not execute code."""
        key = method_key if method_key is not None else self.entry_key
        if key is None:
            raise LoaderError("No unique entry point; pass a CAP method key")
        return self.project.factory.blank_state(addr=self.method_address(key))

    def to_dict(self):
        return {
            "schema": "cap2soot.angr_loader.report/1",
            "loaded": True,
            "versions": {**VERSIONS, "pysoot": self.program.backend_version,
                         "pysoot_revision": self.program.target_revision},
            "backend": type(self.project.loader.main_object).__name__,
            "architecture": self.project.arch.name,
            "simos": type(self.project.simos).__name__,
            "engine": type(self.project.factory.default_engine).__name__,
            "entry_key": self.entry_key,
            "entry_address": str(self.project.entry) if self.project.entry is not None else None,
            "execution_profile": "checked_heap_and_internal_calls",
            "api_profile": None if self.readiness.api is None else self.readiness.api.name,
            "api_models": [] if self.readiness.api is None else sorted(self.readiness.api.models),
            "modeled_external_classes": [] if self.readiness.api is None else [c.name for c in self.readiness.api.classes],
            "heap_policy": {
                "max_array_length": self.project.loader.main_object.cap_max_array_length,
                "allocation_length": "uniquely determined",
                "primitive_array_index": "symbolic if proven within bounds",
                "reference_array_index": "uniquely determined",
                "possible_fault": "error; no paths silently constrained away",
                "merge": "unsupported",
            },
            "supported_features": sorted(SUPPORTED_FEATURES),
            "classes": list(self.program.classes),
            "applets": [asdict(a) for a in self.program.metadata.applets],
            "methods": [
                {"key": key, "signature": str(self.index.descriptors[key]),
                 "attrs": list(method.attrs), "returns": method.ret,
                 "blocks": len(method.blocks),
                 "statements": sum(len(b.statements) for b in method.blocks),
                 "execution_ready": not self.readiness.issues(key),
                 "execution_issues": [i.to_dict() for i in self.readiness.issues(key)],
                 "reachable_methods": self.readiness.reachable(key),
                 "reachable_static_methods": tuple(k for k in self.readiness.reachable(key)
                                                     if 'STATIC' in self.program.methods[k].attrs)}
                for key, method in self.program.methods.items()
            ],
            "external_classes": list(self.program.external_classes),
            "external_methods": [asdict(m) for m in self.program.external_methods],
            "external_fields": [asdict(f) for f in self.program.external_fields],
            "unresolved_symbols": list(self.program.unresolved_symbols),
            "required_backend_features": list(self.program.required_backend_features),
            "notes": [
                "Loaded does not mean the applet has been initialized or executed.",
                "External method bodies are not fabricated; API declarations/models require an explicit profile.",
                "Objects, instance fields, arrays and references use the path-local CAP heap.",
                "API support depends on the selected profile; OwnerPIN, full JCRE/firewall and power-loss recovery are not implemented.",
                "Possible heap faults stop the state with diagnostics; Java exception handlers are not dispatched.",
                "State preparation rejects unsupported reachable methods; errors are never skipped.",
                "Execution readiness checks operations; state-dependent heap guards still apply at runtime.",
                "A prepared instance receiver/base_state is supplied explicitly; install is not run implicitly.",
                "The optional name1 profile uses bounded Python API models and concrete DES; it does not execute native firmware.",
            ],
        }

    def export(self, output_dir):
        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        report = self.to_dict()
        (root / "load_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        locations = [loc.to_dict() for loc in self.index.locations.values()]
        (root / "addresses.json").write_text(json.dumps(locations, ensure_ascii=False, indent=2), encoding="utf-8")
        lines = ["angr project loaded (loader report; execution results are separate)",
                 f"Backend: {report['backend']}; architecture: {report['architecture']}",
                 f"Entry CAP key: {self.entry_key}", f"Entry address: {report['entry_address']}",
                 f"Classes: {len(report['classes'])}; methods: {len(report['methods'])}",
                 f"Unresolved symbols: {len(report['unresolved_symbols'])}",
                 f"API profile: {report['api_profile'] or 'disabled'}", ""]
        for method in report["methods"]:
            lines.append(f"{method['key']}: {method['signature']}")
            lines.append(f"  Execution ready in loader profile: {method['execution_ready']}")
            for issue in method["execution_issues"]:
                lines.append(f"  [{issue['code']}] {issue['method_key']} label {issue['unit_label']}: {issue['message']}")
        lines.extend(["", *report["notes"]])
        (root / "load_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


class AngrLoader:
    def load(self, program: AdaptedProgram, *, entry_key: str | None = None, max_array_length=4096, api_profile=None) -> LoadedProgram:
        if not isinstance(program, AdaptedProgram):
            raise LoaderError("AngrLoader.load expects AdaptedProgram, not diagnostic JSON or a CAP path")
        if type(max_array_length) is not int or not 0 <= max_array_length <= 32767:
            raise LoaderError("max_array_length must be an integer in [0, 32767]")
        deps = load_dependencies()
        from .backend import CAPSootBackend
        from .runtime import CAPSimOS, CheckedSootEngine

        index = MethodIndex(program, deps.arch)
        if entry_key is None:
            installs = {a.install_method_key for a in program.metadata.applets}
            if len(installs) == 1:
                entry_key = next(iter(installs))
            elif not installs and len(program.methods) == 1:
                only_key = next(iter(program.methods))
                method = program.methods[only_key]
                if method.blocks and not {"NATIVE", "ABSTRACT"}.intersection(method.attrs):
                    entry_key = only_key
        if entry_key is not None:
            index.entry(entry_key)
        if api_profile not in (None, 'name1'):
            raise LoaderError(f'Unknown Java Card API profile: {api_profile}')
        if api_profile == 'name1':
            from .javacard_api import Name1API
            api = Name1API()
        else:
            api = None
        readiness = ExecutionReadiness(program, index, api)
        backend = CAPSootBackend(program, index, readiness, entry_key, max_array_length=max_array_length)
        project = deps.angr.Project(backend, auto_load_libs=False, use_sim_procedures=False,
                                    simos=CAPSimOS, engine=CheckedSootEngine)
        return LoadedProgram(program, project, index, readiness, entry_key, deps)

