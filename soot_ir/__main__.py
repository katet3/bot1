"""python -m soot_ir jvm_output --symbols symbols.json --output soot_output"""
from pathlib import Path
import argparse
import json

from . import LoweringError, SootIRBuilder, SymbolTable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="One Method JSON or a directory with method_*.json")
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        files = sorted(args.input.glob("method_*.json")) if args.input.is_dir() else [args.input]
        if not files:
            raise LoweringError("No method_*.json input files")
        if any(p.resolve().is_relative_to(args.output.resolve()) for p in files):
            raise LoweringError("Choose a separate output directory to preserve input JSON files")
        inputs = [json.loads(p.read_text(encoding="utf-8-sig")) for p in files]
        symbols = SymbolTable.from_dict(json.loads(args.symbols.read_text(encoding="utf-8-sig")))
        program = SootIRBuilder(symbols).build_program(inputs)
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "program.json").write_text(program.to_json() + "\n", encoding="utf-8")
        for index, method in enumerate(program.methods):
            (args.output / f"method_{index}.json").write_text(method.to_json() + "\n", encoding="utf-8")
            (args.output / f"method_{index}.jimple").write_text(method.to_text(), encoding="utf-8")
        print(f"Built {len(program.methods)} methods, {sum(len(m.units) for m in program.methods)} units")
        if program.unresolved_symbols:
            print(f"External symbol bindings pending: {len(program.unresolved_symbols)}; see program.json")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"soot_ir: {exc}\n")


if __name__ == "__main__":
    main()
