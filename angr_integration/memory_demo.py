"""Execute an instance method with this, an object field and a byte array."""
import argparse
import json
from pathlib import Path

from pysoot_adapter import ClassMetadata, FieldMetadata, MethodMetadata, ProgramMetadata, PySootAdapter
from soot_ir import Expr, FieldRef, Local, Method, MethodRef, Program, Unit, Value
from soot_ir.builder import make_blocks

from .loader import AngrLoader
from .state import SymbolicArgument


OWNER, KEY = "demo.HeapCell", "demo:heap"


def build_example():
    def local(name, type_):
        return Value("local", type_, name=name)

    def constant(value, type_="int"):
        return Value("constant", type_, value=value)

    def unit(label, kind, **kwargs):
        return Unit(label, kind, label * 2, 0, **kwargs)

    this, x, wide = local("self", OWNER), local("x", "short"), local("wide", "int")
    data, byte, result = local("data", "byte[]"), local("b", "byte"), local("result", "short")
    buffer_ref = FieldRef("buffer", OWNER, "buffer", "byte[]", False)
    value_ref = FieldRef("value", OWNER, "value", "short", False)
    first = Expr("array", "byte", (data, constant(0)))
    units = (
        unit(0, "identity", left=this, right=Value("this", OWNER)),
        unit(1, "identity", left=x, right=Value("parameter", "short", index=0)),
        unit(2, "assign", left=wide, right=Expr("cast", "int", (x,))),
        unit(3, "assign", left=data, right=Expr("new_array", "byte[]", (constant(2),))),
        unit(4, "assign", left=Expr("field", "byte[]", (this,), field=buffer_ref), right=data),
        unit(5, "if", right=Expr("condition", "boolean", (wide, constant(0)), "lt"), target=8),
        unit(6, "assign", left=first, right=constant(7, "byte")),
        unit(7, "goto", target=9),
        unit(8, "assign", left=first, right=constant(-7, "byte")),
        unit(9, "assign", left=byte, right=first),
        unit(10, "assign", left=result, right=Expr("cast", "short", (byte,))),
        unit(11, "assign", left=Expr("field", "short", (this,), field=value_ref), right=result),
        unit(12, "return", right=result),
    )
    method = Method("update", MethodRef(KEY, OWNER, "update", ("short",), "short", False),
                    tuple(Local(v.name, v.type) for v in (this, x, wide, data, byte, result)),
                    units, make_blocks(units, ()), (), tuple((u.offset, (u.label,)) for u in units))
    metadata = ProgramMetadata((ClassMetadata(OWNER, "java.lang.Object", fields=(
        FieldMetadata("value", "value", "short"), FieldMetadata("buffer", "buffer", "byte[]"),
    ), methods=(MethodMetadata(KEY, "update", ("short",), "short", ("PUBLIC",)),)),))
    return PySootAdapter().build(Program((method,), ()), metadata)


def signed(value, bits=32):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def run_demo(output_dir):
    loaded = AngrLoader().load(build_example())
    base = loaded.create_heap_state()
    receiver = base.cap_heap.new_object(OWNER)
    state = loaded.create_call_state(args=[SymbolicArgument("input_short")], receiver=receiver, base_state=base)
    manager = loaded.project.factory.simgr(state).run(n=30)
    if manager.errored:
        manager.errored[0].reraise()
    if manager.active or len(manager.deadended) != 2:
        raise RuntimeError("Memory demo did not finish both paths")
    paths = []
    for end in manager.deadended:
        heap = end.cap_heap
        array = heap.read_field(receiver, OWNER, "buffer", "byte[]")
        path = {
            "input_signed": signed(end.solver.eval(end.globals["cap2soot.inputs"][0]), 16),
            "return_value": signed(end.solver.eval(end.regs.invoke_return_value)),
            "field_value": signed(end.solver.eval(heap.read_field(receiver, OWNER, "value", "short"))),
            "array_signed": [signed(end.solver.eval(heap.read_array(array, i))) for i in range(2)],
            "constraints": [str(c) for c in end.solver.constraints],
        }
        if path["field_value"] != path["return_value"] or path["array_signed"] != [path["return_value"], 0]:
            raise RuntimeError("Heap result disagrees with return value")
        paths.append(path)
    paths.sort(key=lambda p: p["return_value"])
    unchanged = (base.solver.eval(base.cap_heap.read_field(receiver, OWNER, "value", "short")) == 0 and
                 isinstance(base.cap_heap.read_field(receiver, OWNER, "buffer", "byte[]"), loaded.dependencies.arch.SootNullConstant))
    if not unchanged or [p["return_value"] for p in paths] != [-7, 7]:
        raise RuntimeError("Memory paths leaked writes into each other or the base state")
    result = {
        "example": "synthetic instance method; not example.cap execution",
        "deadended": len(manager.deadended), "errored": len(manager.errored), "active": len(manager.active),
        "base_state_unchanged": unchanged, "paths": paths,
    }
    root = Path(output_dir)
    loaded.export(root)
    (root / "execution.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "outputs" / "angr_memory_demo")
    args = parser.parse_args()
    print(json.dumps(run_demo(args.output_root), ensure_ascii=False, indent=2))
    print(f"Результаты: {args.output_root.resolve()}")


if __name__ == "__main__":
    main()
