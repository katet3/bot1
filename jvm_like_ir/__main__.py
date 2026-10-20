"""python -m jvm_like_ir example.cap --output jvm_ir_output"""
import argparse
from pathlib import Path

from jcvm_ir import IRBuilder, ReferenceResolver, methods_from_cap
from .builder import JVMLikeIRBuilder


def main():
    from cap_decompile.container.cap_container import CAPContainer
    from cap_decompile.model.cap_file import CAPFileBuilder

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cap', type=Path)
    parser.add_argument('--output', type=Path, default=Path('jvm_ir_output'))
    args = parser.parse_args()
    container = CAPContainer(args.cap)
    container.load()
    cap = CAPFileBuilder.build(container)
    jcvm_builder = IRBuilder(ReferenceResolver(cap))
    builder = JVMLikeIRBuilder()
    results = [builder.build(jcvm_builder.build(m)) for m in methods_from_cap(cap)]
    args.output.mkdir(parents=True, exist_ok=True)
    for index, ir in enumerate(results):
        (args.output / f'method_{index}.json').write_text(ir.to_json(), encoding='utf-8')
        (args.output / f'method_{index}.txt').write_text(ir.to_text(), encoding='utf-8')
        count = sum(len(b.statements) for b in ir.blocks)
        print(f'METHOD {index}: {len(ir.blocks)} blocks, {len(ir.edges)} edges, {count} statements')


if __name__ == '__main__':
    main()
