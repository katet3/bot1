"""Запуск этапов CAP -> CFG -> JCVM IR -> JVM-like IR -> Soot IR -> pysoot -> angr."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from cap_decompile.container.cap_container import CAPContainer
from cap_decompile.model.cap_file import CAPFile, CAPFileBuilder
from cfg_generator.generator import CFGGenerator
from cfg_generator.model.cfg import CFG
from cfg_generator.visualization.ascii_exporter import ASCIIExporter
from jcvm_ir import IRBuilder, MethodInput, ReferenceResolver, methods_from_cap
from jcvm_ir import MethodIR as JCVMMethodIR
from jvm_like_ir import JVMLikeIRBuilder
from jvm_like_ir import Method as JVMMethodIR
from soot_ir import Program, SootIRBuilder, SymbolTable
from soot_ir import Method as SootMethodIR
from pysoot_adapter import AdaptedProgram, PySootAdapter, metadata_from_cap
from verification_engine.verifier import Verifier


PROJECT_DIR = Path(__file__).resolve().parent


def load_cap(cap_path: Path) -> CAPFile:
    """Прочитать CAP-контейнер, разобрать компоненты и связать модель."""
    container = CAPContainer(cap_path)
    container.load()
    return CAPFileBuilder.build(container)


def extract_methods(cap_file: CAPFile) -> list[MethodInput]:
    """Получить инструкции методов вместе с сигнатурами и метаданными."""
    methods = list(methods_from_cap(cap_file))
    if not methods:
        raise ValueError("В CAP-файле нет методов для обработки")
    return methods


def build_cfgs(methods: Sequence[MethodInput]) -> list[CFG]:
    """Построить CFG для каждого метода, сохраняя порядок методов."""
    generator = CFGGenerator()
    return [generator.build(method) for method in methods]


def verify_methods(methods: Sequence[MethodInput]) -> None:
    """Проверить методы через текущий публичный API Verifier.

    Verifier.verify(method) сам строит CFG для проверки. Пока его API не
    принимает готовый cfg, здесь сохраняется именно этот способ вызова.
    """
    verifier = Verifier()
    for index, method in enumerate(methods):
        report = verifier.verify(method=method)
        if not report.success:
            raise ValueError(
                f"Верификация METHOD {index} ({method.name}) не пройдена:\n"
                f"{report.to_text()}"
            )


def build_jcvm_ir(
    cap_file: CAPFile,
    methods: Sequence[MethodInput],
    cfgs: Sequence[CFG],
    *, interface_signatures: dict | None = None,
) -> list[JCVMMethodIR]:
    """Нормализовать JCVM-инструкции и проверить их стековую семантику."""
    builder = IRBuilder(ReferenceResolver(cap_file, interface_signatures))
    return [
        builder.build(method, cfg=cfg)
        for method, cfg in zip(methods, cfgs, strict=True)
    ]


def build_jvm_like_ir(methods: Sequence[JCVMMethodIR]) -> list[JVMMethodIR]:
    """Устранить стек и получить явные значения и параметры блоков."""
    builder = JVMLikeIRBuilder()
    return [builder.build(method) for method in methods]


def load_symbols(symbols_path: Path) -> SymbolTable:
    """Загрузить общую таблицу имён для Soot IR и pysoot adapter."""
    config = json.loads(symbols_path.read_text(encoding="utf-8-sig"))
    return SymbolTable.from_dict(config)


def build_soot_ir(
    methods: Sequence[JVMMethodIR], symbols: SymbolTable
) -> Program:
    """Построить Soot IR для всех методов и разрешить внутренние вызовы."""
    return SootIRBuilder(symbols).build_program(methods)


def build_pysoot_model(
    cap_file: CAPFile, program: Program, symbols: SymbolTable
) -> AdaptedProgram:
    """Передать объявления классов CAP и построить объекты pysoot."""
    metadata = metadata_from_cap(cap_file, symbols)
    return PySootAdapter().build(program, metadata)


def load_angr_program(program: AdaptedProgram, *, entry_key: str | None = None, api_profile=None):
    """Создать angr.Project; не запускать install/process и исследование путей."""
    from angr_integration import AngrLoader
    return AngrLoader().load(program, entry_key=entry_key, api_profile=api_profile)


def export_ir_methods(
    methods: Iterable[JCVMMethodIR | JVMMethodIR | SootMethodIR],
    output_dir: Path,
    text_suffix: str = ".txt",
) -> None:
    """Сохранить JSON и читаемый текст каждого метода."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for index, method in enumerate(methods):
        stem = f"method_{index}"
        (output_dir / f"{stem}.json").write_text(
            method.to_json(), encoding="utf-8"
        )
        (output_dir / f"{stem}{text_suffix}").write_text(
            method.to_text(), encoding="utf-8"
        )


def export_soot_ir(program: Program, output_dir: Path) -> None:
    """Сохранить тела методов и общую модель Soot-программы."""
    export_ir_methods(program.methods, output_dir, text_suffix=".jimple")
    (output_dir / "program.json").write_text(
        program.to_json(), encoding="utf-8"
    )


def export_cfgs(
    cfgs: Sequence[CFG], output_dir: Path, *, render_png: bool = True
) -> None:
    """Сохранить текстовые графы и, при необходимости, PNG."""
    output_dir.mkdir(parents=True, exist_ok=True)
    text_exporter = ASCIIExporter()
    for index, cfg in enumerate(cfgs):
        (output_dir / f"method_{index}.txt").write_text(
            text_exporter.export(cfg), encoding="utf-8"
        )
    if not render_png:
        return
    # Graphviz нужен только для рисунков.
    try:
        from cfg_generator.visualization.dot_exporter import DotExporter
    except ModuleNotFoundError as exc:
        if exc.name != "graphviz":
            raise
        raise RuntimeError(
            "Для PNG установите Python-пакет graphviz или используйте --no-png"
        ) from exc
    if shutil.which("dot") is None:
        raise RuntimeError(
            "Для PNG установите Graphviz и добавьте dot в PATH "
            "или используйте --no-png"
        )
    image_exporter = DotExporter()
    for index, cfg in enumerate(cfgs):
        # Private-токен 255 может повторяться: индекс даёт уникальное имя.
        image_exporter.export(
            cfg,
            output_path=(output_dir / f"method_{index}").as_posix(),
            format="png",
        )


def print_debug_output(methods: Sequence[MethodInput], cfgs: Sequence[CFG]) -> None:
    """Показать инструкции и CFG отдельно от этапов преобразования."""
    exporter = ASCIIExporter()
    for index, (method, cfg) in enumerate(zip(methods, cfgs, strict=True)):
        print("=" * 60)
        print(f"METHOD {index}: {method.name}")
        print("=" * 60)
        for instruction in method.instructions:
            print(instruction)
        print()
        print(exporter.export(cfg))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cap", type=Path, default=PROJECT_DIR / "example.cap",
        help="Входной CAP-файл (по умолчанию example.cap рядом с main.py)",
    )
    parser.add_argument(
        "--symbols", type=Path,
        default=PROJECT_DIR / "soot_ir" / "soot_symbols.example.json",
        help="Конфигурация символов Soot IR",
    )
    parser.add_argument(
        "--output-root", type=Path, default=PROJECT_DIR / "outputs",
        help="Общий каталог результатов (по умолчанию outputs рядом с main.py)",
    )
    parser.add_argument("--no-png", action="store_true", help="Сохранить CFG только текстом")
    parser.add_argument("--quiet", action="store_true", help="Не печатать инструкции и CFG")
    parser.add_argument("--no-pysoot", action="store_true", help="Завершить конвейер на Soot IR")
    parser.add_argument("--no-angr", action="store_true", help="Завершить конвейер до загрузчика angr")
    parser.add_argument("--angr-entry", help="Устойчивый CAP-ключ метода входа (из pysoot_output/program.json)")
    parser.add_argument('--javacard-profile', choices=('name1',), help='Явно включить ограниченные модели API для name1; без исполнения')
    args = parser.parse_args(argv)
    if args.angr_entry and (args.no_angr or args.no_pysoot):
        parser.error("--angr-entry нельзя использовать вместе с --no-angr или --no-pysoot")
    if args.javacard_profile and (args.no_angr or args.no_pysoot):
        parser.error('--javacard-profile требует загрузки angr')
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        # 1. CAP: компоненты, методы и инструкции.
        cap_file = load_cap(args.cap)
        methods = extract_methods(cap_file)

        # 2. CFG и проверка до преобразования в IR.
        cfgs = build_cfgs(methods)
        verify_methods(methods)

        # 3–5. Последовательные представления программы.
        symbols = load_symbols(args.symbols)
        jcvm_methods = build_jcvm_ir(cap_file, methods, cfgs,
                                    interface_signatures=symbols.interface_signatures)
        jvm_methods = build_jvm_like_ir(jcvm_methods)
        program = build_soot_ir(jvm_methods, symbols)

        # 6. Объекты pysoot и метаданные классов CAP.
        pysoot_program = None
        if not args.no_pysoot:
            pysoot_program = build_pysoot_model(cap_file, program, symbols)

        # 7. Загрузка объектов в angr. Исполнение апплета — отдельный этап.
        loaded_program = None
        if pysoot_program is not None and not args.no_angr:
            loaded_program = load_angr_program(pysoot_program, entry_key=args.angr_entry, api_profile=args.javacard_profile)

        # 8. Сохранение результатов в едином каталоге outputs/.
        export_ir_methods(jcvm_methods, args.output_root / "ir_output")
        export_ir_methods(jvm_methods, args.output_root / "jvm_ir_output")
        export_soot_ir(program, args.output_root / "soot_output")
        if pysoot_program is not None:
            pysoot_program.export(args.output_root / "pysoot_output")
        if loaded_program is not None:
            loaded_program.export(args.output_root / "angr_output")
        export_cfgs(cfgs, args.output_root / "cfg_output", render_png=not args.no_png)

        if not args.quiet:
            print_debug_output(methods, cfgs)
        print(f"Обработано методов: {len(program.methods)}")
        print(f"Результаты: {args.output_root.resolve()}")
        if pysoot_program is not None:
            print(f"pysoot: классов {len(pysoot_program.classes)}, методов {len(pysoot_program.methods)}")
        if loaded_program is not None:
            print(f"angr: проект загружен; вход: {loaded_program.entry_key}")
            print("Исполнение апплета не запускалось; ограничения указаны в angr_output/load_report.txt")
        unresolved = pysoot_program.unresolved_symbols if pysoot_program is not None else program.unresolved_symbols
        if unresolved:
            print(f"Внешних символов без привязки: {len(unresolved)}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Ошибка конвейера: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
