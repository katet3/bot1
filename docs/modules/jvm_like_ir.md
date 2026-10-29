# jvm_like_ir — устранение operand stack

[К документации](../README.md) · [Построитель](../../jvm_like_ir/builder.py)

## Назначение и контракт

`JVMLikeIRBuilder().build(source)` принимает проверенный `jcvm_ir.MethodIR`
и выдаёт immutable `jvm_like_ir.Method`. Временные значения имеют явные имена,
а перенос остатка стека между блоками выражен block parameters и edge arguments.
Это промежуточная форма для Soot, не Java class file и не полный SSA/Shimple.
Local slots, поля и массивы сохраняют изменяемую семантику.

Обязательны signature, непустое тело, корректный entry и проверенные input/output
stacks **всех** блоков. Недостижимый блок с неизвестным stack type не удаляется
молча: builder возвращает `LoweringError`.

## Модули

| Файл | Основные определения | Ответственность |
| --- | --- | --- |
| `model.py` | `ValueType`, `Value`, `Constant`, `Argument`, `Statement`, `Terminator`, `Edge`, `Block`, `Method`, `LoweringError` | Контракт представления без стека; schema_version=1 |
| `builder.py` | `JVMLikeIRBuilder` | Stack elimination и сохранение эффектов/координат |
| `validation.py` | `validate`, `require`, `_statement_types`, `_store`, `_validate_locals` | Типы, edges, use-before-definition, локальные слоты и handler annotations |
| `text.py` | `operand`, `reference`, `format_statement`, `format_method` | Читаемый дамп без изменения IR |
| `__main__.py` | `main` | Отдельный CLI CAP → JVM-like IR; ограниченный набор входных опций |
| `__init__.py` | Реэкспорты | Builder и публичные типы |

## Модель данных

`ValueType` имеет SHORT/INT/REFERENCE. `Value` — имя и вычислительный тип;
`Constant` — тип и immediate value. `Argument` хранит **номер локального слота**,
declared type и признак receiver. Он не равен индексу параметра Java: int занимает
два слота, receiver — первый слот instance method.

`Statement` содержит op, operands, optional result, semantic_type, local index,
Reference, mode, may_throw и ordered handler_indices. `Terminator` описывает
branch/goto/switch/return/throw. `Edge.arguments` передают значения параметрам
целевого блока. Exception edge не несёт обычных stack arguments: handler получает
отдельное исключение. `Block.source_offsets` сохраняет также устранённые операции.

## Почему используются параметры блоков

Стек в точке соединения может содержать значения разных предыдущих вычислений.
Его форма уже проверена JCVM builder-ом, поэтому вход блока описывается набором
типизированных параметров. Каждое обычное ребро передаёт конкретные значения.
Использование значения из другого блока без параметра запрещено валидатором.
Это явный контракт для следующей стадии, которая реализует передачу копированиями.

Псевдосхема: оба предшественника передают свой short в `B2(p0: short)`. Тело B2
работает с `p0`, а не пытается угадывать источник по имени временного значения.
Loops используют тот же механизм на обратных рёбрах.

## Порядок эффектов и числовая семантика

Builder обходит операции в исходном порядке. Load local материализует значение
в момент чтения. `dup` копирует ссылку на уже вычисленный immutable value, поэтому
не повторяет read, new или call. `sinc/iinc` раскладываются на load/add/store.
Неявный `_this` field access получает явный receiver из local 0.

`s2b/i2b` сохраняют факт narrowing до byte с последующим использованием short
stack kind. `sushr` специально расширяется до int, выполняет logical right shift
и сужается обратно до short; 16-битный logical shift сам по себе неверен.
Следующая стадия дополнительно задаёт Soot casts и mask величины сдвига.

Операции, способные бросить исключение, сохраняют handler indices по offset:
allocation, references/arrays, call/checkcast, div/rem. Порядок handler table
не теряется, хотя runtime dispatch ещё не реализован.

## Validation

Проверяются уникальность IDs/starts/names, типы operands/results, принадлежность
source offsets, arity, сигнатура аргументов и возврата, типы block parameters,
набор normal edges и порядок conservative exceptional edges. Constants обязаны
попадать в signed диапазон 16/32 бит; immediate reference может быть только null.

Dataflow локальных слотов моделирует definite assignment, receiver/arguments,
двухслотовый int и перезапись пересекающихся слотов. Слияние не объявляет слот
инициализированным, если это не доказано по входящим путям. Exception paths
учитывают состояние до возможного throwing effect.

## CLI и интеграция

Основной рекомендуемый путь — корневой `main.py` с CAP/symbols и, при необходимости,
`--no-pysoot`. Он сохраняет `jvm_ir_output/method_N.json` и `.txt`.

У standalone `python -m jvm_like_ir CAP --output DIR` нет опции symbols и передачи
`interface_signatures`. Поэтому его нельзя рекомендовать для текущего `name1`,
использующего `DESKey.setKey` через interface. Это ограничение отдельной утилиты,
а не запрет на такой CAP в главном pipeline.

## Как расширять

Новая операция должна сохранить тип результата, исходный offset, порядок эффектов
и may_throw/handler indices. Нельзя заменять load на повторное вычисление после
записи или константно сворачивать недоказанное значение. Для операций со стеком
проверяйте словесную ширину, особенно int и dup2/pop2. При новом типе добавляйте
правило validation до разрешения операции в output.

Критические регрессии: alias при dup, несколько predecessors, loop/back-edge
перестановка, narrowing и обработчик на границе локальной записи. Существующие
adapter/integration тесты проходят эту стадию, но отдельная исчерпывающая матрица
всех lowering-операций не заявляется.
