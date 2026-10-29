# angr_integration — загрузчик, checked execution и CAP heap

[К документации](../README.md) · [Java Card runtime](javacard_runtime.md)

## Назначение и основные API

`AngrLoader().load(adapted, entry_key=None, max_array_length=4096, api_profile=None)`
создаёт `LoadedProgram`. Вход — настоящий `AdaptedProgram`, не CAP path и не
диагностический JSON. Поддержаны профили `None` и `'name1'`. Переданный explicit
entry проверяется, но не исполняется. Размер массива ограничивается значением
0..32767; это analysis limit, а не модель ёмкости памяти карты.

`LoadedProgram` предоставляет доступ к `project`, `program`, `index`, `readiness`,
`dependencies`, entry key и следующим операциям:

| Метод | Контракт |
| --- | --- |
| `method_address(key)` | Entry Soot address конкретного метода |
| `address_for_label(key, label)` | Адрес по Unit label |
| `addresses_for_offset(key, offset)` | Кортеж адресов; соответствие может быть пустым или множественным |
| `source_location(address)` | Обратная связь с CAP и IR origins |
| `create_heap_state(key=None)` | Пустые heap/Java frames; методы не запускаются |
| `create_call_state(key=None, args=(), receiver=None, base_state=None)` | Проверенный вход прямого вызова с return terminator |
| `to_dict()`, `export(directory)` | Отчёт загрузки и адреса; не результат исполнения |

## Карта модулей

| Файл | Определения | Ответственность |
| --- | --- | --- |
| `dependencies.py` | `VERSIONS`, `load_dependencies` | Ленивый импорт и строгая проверка angr/CLE/archinfo |
| `backend.py` | `CAPSootBackend` | In-memory CLE Soot backend без Lifter/JVM |
| `loader.py` | `AngrLoader`, `LoadedProgram` | Композиция, entry selection, профиль, отчёты |
| `index.py` | `SourceLocation`, `MethodIndex` | CAP key/offset ↔ Soot descriptor/block/statement |
| `readiness.py` | `ExecutionIssue`, `ExecutionReadiness`, `walk`, feature sets | Консервативная проверка операций и достижимых вызовов |
| `state.py` | `SymbolicArgument`, `encode_argument`, `create_call_state` | Типизация аргументов, receiver/base_state и установка entry frame |
| `runtime.py` | `CAPSimOS`, `CAPMemoryError`, `CheckedSootEngine` | Java frames, execution boundary, ошибки и call/return protocol |
| `semantics.py` | `CAPInvoke`, `evaluate`, `CAPAssign`, `translate_stmt` | Локальные Soot hooks для heap, calls, references и remainder |
| `calls.py` | `CallTarget`, `CallResolver`, `invocation_mode` | Static/special/virtual/interface resolution |
| `heap_types.py` | `HeapSchema`, predicates, `PRIMITIVES` | Декларации, type compatibility, inherited instance fields |
| `heap.py` | `HeapReference`, `_Array`, `CAPHeap` | Память объектов/массивов на отдельном пути |
| `errors.py` | `LoaderError`, `DependencyError`, `ExecutionNotReady`, `HeapError` | Типизированные границы ошибок |
| `javacard_api.py` | API dataclasses, `JavaCardState`, `Name1API`, helpers | Подробно в [Java Card runtime](javacard_runtime.md) |
| `javacard_session.py` | `CommandFault`, `CommandRun`, `JavaCardSession` | Жизненный цикл install/APDU и выбор состояний |
| `demo.py` | `build_example`, `run_demo`, `main`, `signed` | Синтетическая функция со знаком short и двумя результатами |
| `memory_demo.py` | `build_example`, `run_demo`, `main`, `signed` | Instance receiver, field/array, проверка изоляции fork |
| `name1_demo.py` | `load_name1`, `run_demo`, `main` | Полный неизменённый CAP, API и проверяемые сценарии |
| `__init__.py` | Реэкспорты | Loader, state argument и ошибки |
| `tests/test_loader.py` | `LoaderTests`, helpers | 18 регрессий загрузки/числового исполнения |
| `tests/test_heap.py` | `HeapTests`, helpers | 16 регрессий heap и references |
| `tests/test_calls.py` | `CallTests`, `RemainderTests`, helpers | 6 регрессий вызовов и remainder |
| `tests/test_javacard.py` | `JavaCardTests` | 20 проверок API/session; отдельное руководство |

## Почему нужен собственный backend и engine

Обычный CLE Soot constructor вызывает Lifter. Здесь модели уже построены из CAP,
поэтому `CAPSootBackend` вызывает `Backend.__init__` напрямую и устанавливает
classes/entry/ArchSoot и CAP metadata. Повторно используются lookup/address
возможности Soot, но не Java front-end. Backend не содержит native memory/JNI.

`CAPSimOS.state_blank` создаёт Java frames, register state и CAPHeap без desktop
System.in/out и без implicit initialization. При наличии API регистрирует
JavaCardState. `CheckedSootEngine` использует механизм вызовов/переходов angr,
но не допускает пропуска ошибочного statement и неизвестного метода с выдуманным
return. Глобальные registries angr не monkey-patch-ятся: hooks привязаны к проекту.

Эти hooks зависят от внутреннего API angr `10.0.4.post1`, поэтому обновление
версии требует сверки callsite/return targets, statement translation и ошибок.
`from angr import claripy` соответствует выбранной версии; отдельный импорт
верхнеуровневого claripy не является контрактом этого окружения.

## Execution readiness

Readiness обходит реальные pysoot nodes, сверяет signatures/types, class declarations
и required backend features. Локальные проблемы хранятся по методу, а `issues(key)`
объединяет их для всех транзитивно достижимых внутренних целей. Рекурсивный call
graph обходится через visited set. Разрешение общего feature `java_calls_and_api_models`
не включает все вызовы: каждый call site проверяется отдельно.

Поддержанный numeric subset: add/sub/mul/and/or/xor/rem с int32-результатом,
primitive casts и signed comparisons. References допускают eq/ne, explicit cast,
instance fields, arrays, allocation и аргументы. Проверка actual heap/reference
проводится дополнительно во время исполнения.

Методы с traps/throw, static fields, `<clinit>`, неподдержанными div/shifts/unary
operations, missing bodies и неизвестными API не становятся execution ready.
Класс с initializer также блокирует соответствующие способы подготовки/выделения.
Preflight консервативен: неподдержанная потенциальная цель блокирует вызов, даже
если конкретный вход мог бы не попасть в неё.

## Вызовы

`CAPInvoke` вычисляет receiver, проверяет null/type и выбирает `CallTarget`.
Аргументы нормализуются по declared types. Для loaded target готовятся SootArgument
и frame; instance receiver помечается `is_this_ref=True` для выбранного owner.
Runtime копирует состояние и передаёт управление на entry метода; return target
указывает следующую инструкцию вызывающего метода.

Static ищется по подписи. Special сохраняет объявленную реализацию. Virtual
обходит lineage фактического типа и сопоставляет CAP token плюс params/returns;
private/static/constructor не являются virtual candidates. Synthetic имена
переопределённых методов могут различаться без нарушения dispatch.

Internal interface call пока требует отсутствующей token map и отклоняется.
External interface разрешён только для explicit API implementation. Для вызова
API дополнительно совпадают устойчивый ключ и полная сигнатура. Наличие класса
с таким же Java-именем или похожей подписью не даёт разрешения на подмену модели.

## Подготовка аргументов

`SymbolicArgument(name)` создаёт BVS ширины declared type: byte 8, short 16,
int 32, boolean 1. Примитив расширяется до Soot 32 бит: signed для byte/short,
zero extension для boolean. Integer arguments должны попадать в declared signed
range; boolean — 0/1. Произвольный BV обязан иметь точную исходную ширину.

Повторение имени SymbolicArgument в одном вызове запрещено: для намеренного alias
нужно явно передать один и тот же BV. Reference argument задаётся существующей
HeapReference из `base_state` либо null. Instance receiver требует base_state
того же project и ненулевую совместимую reference. State preparation не вызывает
constructor автоматически. Клиент отвечает за смысл предварительно созданного
receiver; полный JVM uninitialized-object verifier отсутствует.

## CAPHeap: хранение и изоляция

Поля ключуются `(allocation_id, declaring_owner, field_name)`, поэтому скрытые
поля предка и потомка не смешиваются. Schema собирает inherited fields, требует
полную lineage и отклоняет allocation abstract/interface типов. Primitive storage
сужается до declared width и хранится в 32-битном BV; reference сохраняет identity.

Массив — immutable `_Array(element_type, values: tuple)`. Запись создаёт новое
значение вместо изменения общего списка. `copy()` копирует словари; immutable
reference/BV/tuple можно безопасно разделять. UUID allocation IDs различают
объекты, а общие до fork объекты сохраняют ту же identity в обеих копиях.
Merge и widening явно отвергаются.

Primitive array read с symbolic index строит If-цепочку; write строит If для
каждого элемента. Стоимость растёт с длиной массива, поэтому analysis limit
существенен и не равен ограничению CAP/JCRE. Reference array требует unique index:
модель не представляет символический выбор между объектными references.

`read_slice/write_slice` принимают конкретные диапазоны, проверяют bounds до
записи и нормализуют весь набор значений до замены массива. `Util.arrayCopy`
сначала сохраняет source tuple — это обеспечивает overlap semantics. Snapshot
транзакции хранит значения всех persistent fields/arrays, а не журнал отдельных
записей. Allocation во время транзакции запрещён именно в ограниченном профиле.

## Ошибки и полнота анализа

`HeapError` содержит code/message и optional `condition`. Для потенциального
нарушения `_require` сохраняет условие ошибки, не добавляя ограничения, которые
удалили бы опасные входы. Runtime оборачивает его в `CAPMemoryError` с method key,
Unit label и CAP offset; результат находится в `SimulationManager.errored`.

| Код | Смысл |
| --- | --- |
| `null_reference`, `foreign_reference`, `reference_type` | Некорректная reference либо принадлежность heap |
| `class_hierarchy`, `field_declaration`, `allocation_type` | Недостаточно деклараций или неверный тип операции |
| `array_bounds`, `negative_array_size`, `array_store` | Возможная Java memory fault |
| `symbolic_array_size`, `symbolic_reference_index` | Неподдержанная неоднозначность |
| `array_resource_limit` | Аналитический лимит без усечения массива |
| `arithmetic_zero` | Возможный remainder by zero |
| `external_call`, `interface_dispatch`, `call_signature` | Неизвестная или несовместимая цель |
| `global_reference`, `transaction_allocation` | Ограничения явного Java Card профиля |

Остановка потенциально ошибочного состояния сейчас не создаёт одновременно
нормальную и exceptional ветви. Трактовать errored как доказательство ошибки
на всех входах нельзя: смотрите condition. Отсутствие errored при оставшихся
active также не доказывает успех. Для полноты конкретного исследования фиксируются
constraints, границы input domain и лимит шагов.

## Сопровождение и проверки

Новая heap operation должна пройти type/ownership checks и сохранять copy semantics.
Новая arithmetic operation сначала получает регрессии signed/width/edge cases,
затем разрешается readiness. Новая декларация API добавляется явно; создание
всех отсутствующих external классов как пустых нарушило бы проверку layout.

Основные воспроизводимые проверки — suites loader/heap/calls. Минимальные
демонстрации: `python -m angr_integration.demo` и
`python -m angr_integration.memory_demo`. Они строят синтетические тела напрямую
через Soot IR и не являются исполнением произвольного `example.cap`.
