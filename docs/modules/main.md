# main.py — композиция конвейера и CLI

[К документации](../README.md) · [Исходник](../../main.py)

## Назначение и граница ответственности

Корневой `main.py` — точка входа анализа CAP и библиотечный слой сборки конвейера.
Он выбирает входы, вызывает стадии в фиксированном порядке, экспортирует результаты
и печатает итог. Семантика инструкций, heap и API в этом файле не реализуется.
Запуск `main.py`, в том числе с `--javacard-profile`, **не исполняет апплет**.

## Публичные функции

| Функция | Вход → результат | Существенный контракт |
| --- | --- | --- |
| `load_cap(cap_path)` | `Path` → `CAPFile` | Загружает компоненты, вызывает структурную проверку и linker |
| `extract_methods(cap_file)` | `CAPFile` → список `MethodInput` | Использует `methods_from_cap`, отвергает пустой набор |
| `build_cfgs(methods)` | Последовательность методов → список `CFG` | Порядок соответствует входу |
| `verify_methods(methods)` | Методы → `None` | `Verifier.verify(method)` строит отдельный CFG; failure останавливает pipeline |
| `build_jcvm_ir(cap, methods, cfgs, interface_signatures=...)` | CAP/методы/графы → список `MethodIR` | `zip(..., strict=True)`; resolver получает interface signatures до lowering |
| `build_jvm_like_ir(methods)` | JCVM IR → список JVM-like методов | Каждый метод валидируется builder-ом |
| `load_symbols(path)` | JSON UTF-8/UTF-8 BOM → `SymbolTable` | Не дополняет отсутствующие API-подписи догадками |
| `build_soot_ir(methods, symbols)` | Все JVM-like методы → `soot_ir.Program` | Обрабатывает программу целиком для внутренних ссылок |
| `build_pysoot_model(cap, program, symbols)` | Декларации CAP и тела → `AdaptedProgram` | Сначала `metadata_from_cap`, затем `PySootAdapter` |
| `load_angr_program(program, entry_key=None, api_profile=None)` | `AdaptedProgram` → `LoadedProgram` | Лениво импортирует загрузчик angr; не вызывает методы |
| `export_ir_methods(methods, output_dir, text_suffix='.txt')` | Методы → JSON и текст | Индекс `method_N` отражает порядок, не идентичность |
| `export_soot_ir(program, output_dir)` | Soot IR → файлы | Общий `program.json`, тела JSON и `.jimple` |
| `export_cfgs(cfgs, output_dir, render_png=True)` | CFG → текст/PNG | Graphviz импортируется только при запросе PNG |
| `print_debug_output(methods, cfgs)` | Методы/графы → stdout | Не изменяет результаты анализа |
| `parse_args(argv=None)` | CLI → Namespace | Проверяет несовместимые режимы |
| `main(argv=None)` | CLI → код завершения | 0 — завершён конвейер; 1 — перехваченная ошибка; argparse использует 2 |

## Последовательность работы

Сначала CAP связывается с Descriptor и извлекаются методы. Затем строится CFG и
вызывается legacy verifier. Таблица символов загружается **перед** JCVM IR:
подпись `invokeinterface` необходима уже для проверки стека, а не только для
красивого имени в Jimple. После трёх IR-стадий по флагам создаются pysoot и angr.
Экспорт начинается после успешного завершения запрошенных стадий.

Двойное построение CFG (`build_cfgs` и `Verifier`) — текущее устройство публичного
API, а не независимая проверка двумя реализациями. Проверку соответствия графа
инструкциям отдельно выполняет `jcvm_ir.IRBuilder._check_cfg`.

## Аргументы CLI

| Аргумент | Значение по умолчанию | Поведение |
| --- | --- | --- |
| `--cap` | `example.cap` рядом с main.py | Для `name1` необходимо указать его путь явно |
| `--symbols` | `soot_ir/soot_symbols.example.json` | Конфигурация должна соответствовать выбранному CAP |
| `--output-root` | `outputs` рядом с main.py | Корень всех экспортов |
| `--no-png` | Выключен | Экспортирует CFG только текстом |
| `--quiet` | Выключен | Скрывает инструкции и ASCII CFG; logging зависимостей остаётся |
| `--no-pysoot` | Выключен | Завершает на Soot IR; angr также не создаётся |
| `--no-angr` | Выключен | Создаёт pysoot, пропускает angr |
| `--angr-entry` | Автовыбор loader | Полный устойчивый CAP key |
| `--javacard-profile name1` | API выключен | Добавляет модели в загрузчик; исполнения нет |

`--angr-entry` и `--javacard-profile` несовместимы с `--no-angr`/`--no-pysoot`.
Существующий `symbols.example.json` не является универсальной таблицей всех API.

## Примеры

```powershell
.\.venv-angr10\Scripts\python.exe main.py --cap examples/name1/name1.cap --symbols examples/name1/symbols.json --no-png --quiet --output-root outputs/name1
.\.venv-angr10\Scripts\python.exe main.py --cap examples/name1/name1.cap --symbols examples/name1/symbols.json --javacard-profile name1 --no-png --quiet --output-root outputs/name1_api
```

Для исполнения используется отдельный `python -m angr_integration.name1_demo`.
Разделение позволяет изучать IR и ограничения программы, даже когда runtime
ещё не поддерживает её операции.

## Экспорт, ошибки и сопровождение

Функция `main` перехватывает `OSError`, `ValueError`, `RuntimeError`, выводит
`Ошибка конвейера: ...` в stderr и возвращает 1. Произвольные ошибки реализации,
например `TypeError` в legacy verifier, не превращаются в успешный отчёт.
Не следует расширять catch до безусловного подавления всех исключений.

Экспорт создаёт каталоги и перезаписывает одноимённые файлы, но не удаляет лишние
файлы прежнего запуска. Он не атомарный: при проблеме Graphviz ранее записанный
JSON остаётся. Для сравнения результатов используйте новый `--output-root`.

При добавлении стадии требуется определить её вход/выход, способ отключения,
место validation и отдельный каталог экспорта. При изменении symbols проконтролируйте
обоих потребителей: ранний `ReferenceResolver` и поздние Soot/metadata builders.
Проверять CLI следует через согласованный CAP/symbols fixture и режим без PNG;
отдельно — ошибки несовместимых флагов. Основная интеграционная регрессия находится
в [integration_tests/test_name1.py](../../integration_tests/test_name1.py).
