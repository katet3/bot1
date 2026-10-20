# cap2soot/main.py
import json
from pathlib import Path

from cap_decompile.container.cap_container import *
from cap_decompile.model.cap_file import *

from cfg_generator.generator import CFGGenerator
from cfg_generator.visualization.dot_exporter import DotExporter

from jcvm_ir import IRBuilder, ReferenceResolver, methods_from_cap

from jvm_like_ir import JVMLikeIRBuilder

from soot_ir import SootIRBuilder, SymbolTable

def main():
    container = CAPContainer(
        Path("example.cap")
    )

    container.load()

    cap_parsing = CAPFileBuilder.build(container)

    methods = methods_from_cap(cap_parsing)

    ir_builder = IRBuilder(ReferenceResolver(cap_parsing))
    ir_output = Path("ir_output")
    ir_output.mkdir(exist_ok=True)
    for m in methods:
        for ins in m.instructions:
            print(ins)

    jvm_builder = JVMLikeIRBuilder()
    jvm_output = Path("jvm_ir_output")
    jvm_output.mkdir(exist_ok=True)

    generator = CFGGenerator()
    exporter = DotExporter()

    output_dir = Path("cfg_output")
    output_dir.mkdir(exist_ok=True)

    for index, method in enumerate(methods):

        cfg = generator.build(method)

        ir = ir_builder.build(method, cfg=cfg)
        (ir_output / f"method_{index}.json").write_text(
            ir.to_json(),
            encoding="utf-8",
        )
        (ir_output / f"method_{index}.txt").write_text(
            ir.to_text(),
            encoding="utf-8",
        )

        jvm_ir = jvm_builder.build(ir)
        (jvm_output / f"method_{index}.json").write_text(
            jvm_ir.to_json(), encoding="utf-8"
        )
        (jvm_output / f"method_{index}.txt").write_text(
            jvm_ir.to_text(), encoding="utf-8"
        )

        print("=" * 60)
        print(f"METHOD {index}")
        print("=" * 60)

        for block in cfg.blocks:

            print(
                f"\nBLOCK B{block.id} "
                f"[{block.start_offset}..{block.end_offset}]"
            )

            if block.is_entry:
                print("ENTRY")

            if block.is_exit:
                print("EXIT")

            print("Instructions:")

            for ins in block.instructions:
                print(
                    f"  {ins.offset}: "
                    f"{ins.mnemonic} "
                    f"{ins.operands}"
                )

            print(
                f"Successors: {block.successors}"
            )

            print(
                f"Predecessors: {block.predecessors}"
            )

        print("\nEDGES")

        for edge in cfg.edges:
            print(
                f"B{edge.source} "
                f"--{edge.edge_type.name}--> "
                f"B{edge.target}"
            )

        method_name = (
            f"method_{index}"
            if method.token is None
            else f"method_{method.token}"
        )

        from verification_engine.verifier import (
            Verifier
        )

        verifier = Verifier()

        report = verifier.verify(
            method=method
        )
        
        if not report.success:
            print(report.summary())
            print(report.to_text())
            return


        exporter.export(
            cfg,
            output_path=(
                output_dir / method_name
            ).as_posix(),
            format="png"
        )

    config = json.loads(Path("soot_symbols.example.json").read_text(encoding="utf-8"))
    program = SootIRBuilder(SymbolTable.from_dict(config)).build_program(jvm_methods)

if __name__ == "__main__":
    main()