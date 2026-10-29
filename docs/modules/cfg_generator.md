# cfg_generator — граф потока управления

[К документации](../README.md) · [Построитель](../../cfg_generator/builder.py)

## Назначение и модель

Пакет строит граф метода по декодированным инструкциям. Публичный фасад —
`CFGGenerator().build(method)`, вызывающий `build_cfg(method)`. Граф нужен для
визуализации, структурных правил и сопоставления с нормализованным JCVM IR.
Пакет не делает стековый анализ и не доказывает корректность Java-типов.

`BasicBlock` содержит упорядоченные instructions, start/end offsets, списки
successors/predecessors и флаги entry/exit/handler. `end_offset` — смещение
**начала последней инструкции**, а не exclusive конец байтового диапазона.
`CFGEdge` хранит source/target block id и `EdgeType`. `CFG.offset_to_block`
сопоставляет только начала блоков, не все offsets инструкций.

## Алгоритм и предпосылки

`find_leaders` берёт первую инструкцию, цели branches/switch и инструкцию после
условного перехода. `split_basic_blocks` завершает блок на terminator либо перед
следующим leader. `build_edges` добавляет обычные рёбра; `_add_edge` одновременно
обновляет обе adjacency-списки. Затем добавляются exception edges и выставляются
флаги entry/exit. IDs создаются последовательно с нуля; реализация использует
`blocks[id]`, поэтому произвольная перенумерация без изменения алгоритма недопустима.

Для conditional создаются TRUE и FALSE; goto имеет одну цель; switch создаёт
ребро default и рёбра всех cases. Несколько случаев могут вести в один блок,
и дубликаты в списке рёбер допустимы. Значения cases здесь не сохраняются — они
остаются в instruction operands и восстанавливаются в JCVM IR. Return не имеет
исходящего обычного ребра, хотя enum содержит `RETURN`.

| Модуль | Определения | Ответственность |
| --- | --- | --- |
| `generator.py` | `CFGGenerator.build` | Минимальный публичный фасад |
| `builder.py` | `build_cfg` | Оркестрация, entry/exit flags, offset map |
| `analysis/leaders.py` | `find_leaders` | Начала блоков по обычным переходам |
| `analysis/block_splitter.py` | `split_basic_blocks`, `_build_block` | Разбиение и последовательные IDs |
| `analysis/edge_builder.py` | `build_edges`, `_add_edge` | Обычные рёбра и двусторонние adjacency |
| `analysis/exception_edges.py` | `build_exception_edges` | Консервативные рёбра пересекающихся handler regions |
| `model/basic_block.py` | `BasicBlock` | Структура блока и флаги |
| `model/cfg.py` | `CFG` | Граф метода и lookup начала блока |
| `model/edge.py` | `EdgeType`, `CFGEdge` | Типы рёбер и их концы |
| `utils/instruction_utils.py` | `is_conditional_branch`, `is_unconditional_branch`, `is_switch`, `is_return`, `is_terminator` | Классификация mnemonic; критическая общая таблица |
| `visualization/ascii_exporter.py` | `ASCIIExporter.export` | Читаемая текстовая диагностика |
| `visualization/dot_exporter.py` | `DotExporter.export` | Graphviz output/PNG; внешняя утилита `dot` |
| `exporter.py` | Нет | Пустая заготовка; рабочие exporters находятся в visualization |
| `__init__.py` | Нет | Маркер пакета |

## Исключения: текущая граница

Legacy `build_exception_edges` ожидает dict с `start_pc`, `end_pc`, `handler_pc`.
`methods_from_cap` выдаёт `jcvm_ir.Handler` с атрибутами `start`, `end`, `target`.
При непустой таблице это несовместимые контракты. Кроме того, поиск leaders не
добавляет границы handlers, а неизвестная цель обработчика сейчас пропускается.
Для `name1` handler table пуста, поэтому данный дефект не мешает его прохождению.

JCVM builder имеет более строгую модель handler regions, но главный конвейер
сначала проходит legacy CFG. Поэтому наличие traps в поздних IR не означает,
что любой CAP с try/catch уже проходит весь pipeline; тем более это не означает
runtime dispatch Java exceptions.

## Другие ограничения

Классификатор не охватывает все формы decoder: например, conditional `_w` и
`athrow` требуют согласования. Неизвестная branch target может вызвать `KeyError`
до структурного отчёта. Цели должны совпадать с началами инструкций; JCVM IR
дополнительно проверяет это. Флаг `is_exit` зависит от итоговых successors,
включая exception edges; его нельзя считать синонимом return instruction.

## Сопровождение

При новой control-flow инструкции обновляются классификация, leaders, splitter,
edge builder и соответствующая нормализация JCVM. Проверяется обычный и обратный
переход, отсутствие fallthrough после terminator, несколько switch labels на одну
цель и неверная цель. При исправлении handlers нужен единый data contract и
согласованное half-open определение `[start, end)`.

Graphviz нужен только для изображений; экспорт текста используется при
`--no-png`. Нельзя связывать успешность анализа с доступностью рендерера.
Текущие end-to-end регрессии используют `integration_tests/test_name1.py` и
`IRBuilder._check_cfg`; отдельного полного набора негативных unit-тестов CFG пока нет.
