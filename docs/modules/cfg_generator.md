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

`find_leaders` сначала отвергает неподдержанные `jsr/ret`, затем берёт первую
инструкцию, цели branches/switch, инструкцию после каждого terminator и проверенные
границы обработчиков start/end/target. Конец,
равный длине байткода, не создаёт пустого блока. `split_basic_blocks` завершает блок на terminator либо перед
следующим leader. `build_edges` добавляет обычные рёбра; `_add_edge` одновременно
обновляет обе adjacency-списки. Затем добавляются exception edges и выставляются
флаги entry/exit. IDs создаются последовательно с нуля; реализация использует
`blocks[id]`, поэтому произвольная перенумерация без изменения алгоритма недопустима.

Для conditional создаются TRUE и FALSE; goto имеет одну цель; switch создаёт
ребро default и рёбра всех cases. Несколько случаев могут вести в один блок,
и дубликаты в списке рёбер допустимы. Значения cases здесь не сохраняются — они
остаются в instruction operands и восстанавливаются в JCVM IR. Return и `athrow`
не имеют исходящего обычного ребра, хотя enum содержит `RETURN`.
Выделение следующей инструкции в отдельный блок не означает её достижимость.

## Классификация управления

Единые предикаты в `utils/instruction_utils.py` используются при поиске leaders,
разбиении блоков и построении обычных рёбер. Классификация согласована с таблицей
декодера для поддержанного поднабора:

| Семейство | Формы | Поведение CFG |
| --- | --- | --- |
| Conditional | 16 базовых и 16 соответствующих `_w` | TRUE к target, FALSE к следующему блоку |
| Goto | `goto`, `goto_w` | Только target |
| Switch | `stableswitch`, `itableswitch`, `slookupswitch`, `ilookupswitch` | Default и все cases, включая повторяющиеся цели |
| Return | `return`, `sreturn`, `ireturn`, `areturn` | Нет обычного successor |
| Throw | `athrow` | Нет обычного successor; handlers добавляются отдельно |
| Subroutine | `jsr`, `ret` | Явный `ValueError` до создания блоков |

Список `_w` выводится из 16 допустимых базовых условных инструкций. Наличие этого
суффикса у field/increment opcode не делает его переходом. Фиктивные `if_icmp*`
удалены из старой таблицы CFG: декодер проекта их не выдаёт и JCVM lowering их
не поддерживает. Для decoded `icmp` и следующих условных инструкций используются
их собственные операции.

Декодер уже преобразовал относительное смещение в абсолютный method-local target.
CFG не прибавляет offset повторно. `_w` меняет ширину encoded displacement,
но сохраняет вид TRUE/FALSE и правила разбиения. `is_throw` отделён от `is_return`:
совпадает отсутствие normal successor, а семантика завершения различается.

`reject_unsupported_control_flow` просматривает все инструкции, включая недостижимые.
Поддержки return-address для `jsr/ret` нет; они не моделируются как goto или обычное
продолжение. Обычная инструкция после terminator сохраняется в графе отдельным
блоком, чтобы верификатор мог диагностировать недостижимый код.

## Модули

| Модуль | Определения | Ответственность |
| --- | --- | --- |
| `generator.py` | `CFGGenerator.build` | Минимальный публичный фасад |
| `builder.py` | `build_cfg` | Оркестрация, entry/exit flags, offset map |
| `analysis/leaders.py` | `find_leaders` | Проверка unsupported control flow; цели, инструкции после terminators и границы handlers |
| `analysis/handlers.py` | `ExceptionRegion`, `validated_exception_regions` | Общая проверка method-local координат для leaders и exception edges |
| `analysis/block_splitter.py` | `split_basic_blocks`, `_build_block` | Разбиение и последовательные IDs |
| `analysis/edge_builder.py` | `build_edges`, `_add_edge` | Обычные рёбра и двусторонние adjacency |
| `analysis/exception_edges.py` | `build_exception_edges` | Проверка разбиения и консервативные рёбра защищённых блоков |
| `model/basic_block.py` | `BasicBlock` | Структура блока и флаги |
| `model/cfg.py` | `CFG` | Граф метода и lookup начала блока |
| `model/edge.py` | `EdgeType`, `CFGEdge` | Типы рёбер и их концы |
| `utils/instruction_utils.py` | `is_conditional_branch`, `is_unconditional_branch`, `is_switch`, `is_return`, `is_throw`, `is_terminator`, `reject_unsupported_control_flow` | Общая классификация допустимых форм и явный отказ для subroutines |
| `visualization/ascii_exporter.py` | `ASCIIExporter.export` | Читаемая текстовая диагностика |
| `visualization/dot_exporter.py` | `DotExporter.export` | Graphviz output/PNG; внешняя утилита `dot` |
| `exporter.py` | Нет | Пустая заготовка; рабочие exporters находятся в visualization |
| `__init__.py` | Нет | Маркер пакета |

## Контракт обработчиков исключений

Основной вход — `MethodInput` из `jcvm_ir.methods_from_cap`, содержащий
упорядоченный tuple объектов `jcvm_ir.Handler`. Смещения start/end/target отсчитываются
от первого байта тела метода; защищённый диапазон — `[start, end)`.
`methods_from_cap` преобразует координаты Method component ровно один раз.
CFG не интерпретирует сырые `ExceptionHandlerInfo.start_offset/active_length`:
такой вход отклоняется с указанием использовать adapter.

`analysis/handlers.py` читает атрибуты start/end/target без зависимости от
семантического builder JCVM. Для совместимости отдельно поддержан старый Mapping
с ключами `start_pc`, `end_pc`, `handler_pc`, также в method-local координатах.
Это совместимость только CFG API: JCVM IR по-прежнему требует `jcvm_ir.Handler`.
Исходная таблица не заменяется и не сортируется. `ExceptionRegion` — внутреннее
представление только координат; тип исключения и stop_bit остаются в исходном Handler.

Для непустой таблицы требуется `method.bytecodes`. Обе CFG-стадии используют
одинаковую проверку: координаты — целые числа, не bool; диапазон непустой и входит
в тело; start/target совпадают с началами инструкций; end — начало инструкции
или длина тела. Ошибка даёт `ValueError` с индексом обработчика, включая попытку
передать обработчик для пустого тела. Пустая, отсутствующая или None-таблица
не добавляет рёбер на уровне CFG; JCVM отдельно проверяет наличие метаданных.

Перед изменением блоков `build_exception_edges` проверяет, что все требуемые
границы уже являются началами блоков. Это защищает и прямые вызовы функции:
неизвестный target или неразделённый region больше не пропускается. Если любой
обработчик неверен, функция не изменяет flags, successors или predecessors.

После проверки для каждого обработчика, в порядке таблицы, создаются рёбра от
блоков с `start <= block.start_offset < end` к target. Это консервативная модель:
проверки may_throw здесь нет. Вложенные и перекрывающиеся regions, общие цели и
параллельные рёбра сохраняются. `CFGEdge` не хранит тип или приоритет обработчика;
JCVM IR восстанавливает эти сведения из исходной упорядоченной таблицы.

Сохранение handlers и Soot traps не включает runtime dispatch исключений в angr.
Наличие `try/catch` в произвольном CAP также не отменяет ограничений остальных стадий.

## Другие ограничения

Поддержка всех перечисленных форм CFG не означает полного декодирования и
исполнения любого CAP. Неизвестная branch target может вызвать `KeyError`
до структурного отчёта. Цели должны совпадать с началами инструкций; JCVM IR
дополнительно проверяет это. Флаг `is_exit` зависит от итоговых successors,
включая exception edges; его нельзя считать синонимом return instruction.
При throw без локального handler блок имеет `is_exit=True`; с исключительным
successor — False. Это структурный признак, не доказательство нормального возврата.
Расхождение decoder/lowering по ширине npairs у `ilookupswitch` относится к D-08;
его бинарный путь не исправлен классификацией (см. [KNOWN_LIMITS.md](../KNOWN_LIMITS.md)).

## Сопровождение

При новой control-flow инструкции обновляются классификация, leaders, splitter,
edge builder и соответствующая нормализация JCVM. Проверяется обычный и обратный
переход, отсутствие fallthrough после terminator, несколько switch labels на одну
цель и неверная цель. При изменении handlers сохраняются единый data contract,
half-open определение `[start, end)` и исходный порядок таблицы.

Graphviz нужен только для изображений; экспорт текста используется при
`--no-png`. Нельзя связывать успешность анализа с доступностью рендерера.
Регрессии D-04 находятся в `cfg_generator/tests/test_exception_handlers.py`
и `cfg_generator/tests/test_handler_pipeline.py`: 14 проверок CFG и 3 проверки
согласованности IR, включая CAP metadata adapter → CFG → Verifier → JCVM IR →
JVM-like IR → Soot IR. Проверка adapter использует синтетические структуры компонентов,
а не новый бинарный CAP.

В `cfg_generator/tests/test_control_flow.py` находятся 19 регрессий D-05 с subtests:
все 32 условные формы декодируются из байтов, сравниваются с независимым JCVM IR
и проходят в Soot с сохранением relation. Проверяются обратные и дальние `_w`
переходы, совпадение TRUE/FALSE целей, отсутствие fallthrough у goto/return/throw,
взаимодействие throw с handlers и отказ для `jsr/ret`. Четыре switch-формы
проверяются на уровне уже декодированных Instruction, включая общие targets.

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest discover -s cfg_generator/tests -p "test_*.py" -v
```

Набор содержит 36 тестов и использует стандартную библиотеку Python и исходники проекта;
angr, pysoot, Graphviz и реальные CAP-фикстуры не требуются.
