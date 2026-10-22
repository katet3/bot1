"""Run a tiny symbolic method through the actual loader and angr Soot engine."""
import argparse
import json
from pathlib import Path

from pysoot_adapter import ClassMetadata, MethodMetadata, ProgramMetadata, PySootAdapter
from soot_ir import Expr, Local, Method, MethodRef, Program, Unit, Value
from soot_ir.builder import make_blocks

from .loader import AngrLoader
from .state import SymbolicArgument


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def build_example():
    """Equivalent to static int sign(short x) { return x < 0 ? -7 : 7; }."""
    owner, key = "demo.LoaderCheck", "demo:sign"
    x = Value("local", "short", name="x")
    wide = Value("local", "int", name="wide")
    zero = Value("constant", "int", value=0)
    units = (
        Unit(0, "identity", None, None, left=x, right=Value("parameter", "short", index=0)),
        Unit(1, "assign", 0, 0, left=wide, right=Expr("cast", "int", (x,))),
        Unit(2, "if", 0, 0, right=Expr("condition", "boolean", (wide, zero), "lt"), target=4),
        Unit(3, "return", 2, 1, right=Value("constant", "int", value=7)),
        Unit(4, "return", 4, 2, right=Value("constant", "int", value=-7)),
    )
    method = Method("sign", MethodRef(key, owner, "sign", ("short",), "int", True),
                    (Local("x", "short"), Local("wide", "int")), units, make_blocks(units, ()), (),
                    ((0, (1, 2)), (2, (3,)), (4, (4,))))
    metadata = ProgramMetadata((ClassMetadata(owner, "java.lang.Object", attrs=("PUBLIC",), methods=(
        MethodMetadata(key, "sign", ("short",), "int", ("PUBLIC", "STATIC")),
    )),))
    return PySootAdapter().build(Program((method,), ()), metadata)


def run_demo(output_dir):
    loaded = AngrLoader().load(build_example())
    state = loaded.create_call_state(args=[SymbolicArgument("input_short")])
    manager = loaded.project.factory.simgr(state).run(n=12)
    if manager.errored:
        manager.errored[0].reraise()
    if manager.active or len(manager.deadended) != 2:
        raise RuntimeError("Demo did not complete both branches within its step budget")
    paths = []
    for end in manager.deadended:
        value = end.solver.eval(end.globals["cap2soot.inputs"][0])
        paths.append({"input_signed": signed(value, 16), "input_bits_hex": f"0x{value:04x}",
                      "return_value": signed(end.solver.eval(end.regs.invoke_return_value), 32),
                      "constraints": [str(c) for c in end.solver.constraints]})
    paths.sort(key=lambda p: p["return_value"])
    result = {"example": "synthetic primitive method; not the Java Card applet",
              "engine": type(loaded.project.factory.default_engine).__name__,
              "deadended": len(manager.deadended), "errored": len(manager.errored), "paths": paths}
    root = Path(output_dir)
    loaded.export(root)
    (root / "execution.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "outputs" / "angr_demo")
    args = parser.parse_args()
    result = run_demo(args.output_root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"Результаты: {args.output_root.resolve()}")


if __name__ == "__main__":
    main()
