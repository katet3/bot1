# jcvm_ir — типизированная стековая семантика JCVM

[К документации](../README.md) · [Модель](../../jcvm_ir/model.py)

## Назначение

Пакет превращает декодированные инструкции в операции с явными типами, стековыми
эффектами и устойчивыми ссылками. Он проверяет, что декодирование покрывает
исходный байткод и что стеки совместимы на переходах. Это первый семантический
уровень; он ещё сохраняет operand stack и не зависит от angr/pysoot.

Основной вызов: `IRBuilder(ReferenceResolver(cap, interface_signatures)).build(method, cfg=cfg)`.
`method` следует получать из `methods_from_cap(cap)`. Передача упрощённого
`CAPFile.to_model()` не даёт необходимых max_stack/nargs/max_locals/handlers.

## Модули и определения

| Файл | Публичные определения | Обязанность |
| --- | --- | --- |
| `model.py` | `Type`, `Signature`, `Reference`, `Op`, `Operation`, `Handler`, `Edge`, `Block`, `MethodIR`, `IRValidationError` | Канонический typed stack IR и JSON/text export |
| `adapter.py` | `MethodInput`, `methods_from_cap` | Восстановление метаданных методов из CAP/Descriptor |
| `resolver.py` | `DescriptorTypes`, `ReferenceResolver` | Декодирование signatures и разрешение CP references |
| `lowering.py` | `lower` | Instruction → `(Operation, byte_length)` с проверкой operands |
| `builder.py` | `IRBuilder` | CFG normalization, сверка входного CFG, dataflow стеков |
| `__init__.py` | Реэкспорты | Публичный доступ к builder, adapter, resolver и типам |

## Данные и координаты

`MethodInput.offset` — info-relative offset header в Method component.
`Operation.offset`, `Handler.start/end/target` — method-local bytecode coordinates.
При извлечении методов учитывается начало methods blob `1 + 8 * handler_count`
и двухбайтовый ordinary header. Этот расчёт нельзя переносить на extended headers.
После D-06 CAP linker корректно читает extended header размером 4 байта, но adapter
отклоняет его до декодирования тела и сдвига `+2`. Структурная поддержка формата
и разрешение преобразования в typed IR остаются разными контрактами.

CFG принимает этот же `Handler` без повторного сдвига координат, выделяет
start/end/target в начала блоков и проверяет границы `[start, end)`. Его внутренний
`ExceptionRegion` хранит только координаты; каноническая таблица Handler остаётся
источником catch_type_index, stop_bit и приоритетов для последующих стадий.
Поддержка старых dict в CFG не распространяется на `IRBuilder`: здесь по-прежнему
требуются объекты `jcvm_ir.Handler`.

`Reference` хранит CP index для диагностики и отдельную идентичность:
AID/version, external flag, class token/offset, member token/internal offset,
signature либо field_type. Подпись `Signature` хранит параметры и return type.
В таблице Descriptor return type идёт последним; void в списке параметров запрещён.

| Тип | `stack_kind` | JCVM slots |
| --- | --- | --- |
| `boolean`, `byte`, `short` | `short` | 1 |
| `int` | `int` | 2 |
| `reference`, массив | `reference` | 1 |
| `void` | `void` | 0 |

Список `pops` упорядочен снизу вверх снимаемой части стека. Receiver instance call
расположен перед параметрами. `Operation` содержит исходную mnemonic, поэтому
семантическая нормализация не уничтожает диагностическую связь с CAP.

## Алгоритм построения

Builder проверяет числовые ограничения заголовка, тип handlers и непрерывность
instructions. Для каждой инструкции `lower` возвращает семантику и длину, затем
проверяются opcode/source match и итоговое покрытие bytes.

Leaders включают branch targets, инструкции после terminators, начала/концы
защищённых диапазонов и handler entries. Handler interval — `[start, end)`.
Обычный граф строится из нормализованных операций; switch сохраняет default и
значения каждого case. Exception edges содержат индекс исходного handler и его
порядок. Переданный CFG сравнивается по блокам и мультимножеству обычных рёбер.

После D-05 ранний CFG использует согласованную классификацию 32 условных форм
(включая `_w`) и не добавляет обычное ребро после `athrow`. Инструкции после всех
terminators выделяются в отдельные блоки. Преобразование условных `_w` в `Op.BRANCH`
и `athrow` в `Op.THROW` уже выполнялось этим IR; исправление устраняет рассогласование
предыдущей стадии, не добавляет runtime exception dispatch.

Стековый dataflow начинается с пустого entry stack. Для каждой операции проверяется
совпадение требуемых pops, выполняются pushes и проверяется max_stack в **словах**.
На обычном ребре передаётся итоговый стек; на exceptional — одна reference.
Два входа блока обязаны иметь одинаковую форму стека. Недостижимому блоку ставится
warning и остаётся неизвестный stack; следующая стадия такой метод отвергает.

`dup2/pop2` работают по числу слотов: нельзя разрезать `int` пополам.
Проверка индексов locals учитывает `nargs + max_locals`, а не только max_locals.
Return сопоставляется с signature по stack kind.

## Ссылки и invokeinterface

`ReferenceResolver.resolve` проверяет CP index, допустимые tags, import package
token и descriptor offset. Для поля требуется ровно один non-void тип; для
method reference извлекается полная signature. Имена API здесь не угадываются.

У `invokeinterface` в CP находится Classref, а signature вызываемого метода
не следует из одного nargs. Поэтому `resolve_interface` требует внешнюю
`interface_signatures` запись. Для name1 она выглядит так:

```json
{
  "a0000000620102@1.5:c10:t1:m5": {
    "parameters": [{"kind": "byte[]"}, {"kind": "short"}],
    "returns": {"kind": "void"}
  }
}
```

Проверяется `1 + sum(parameter.slots) == nargs`, где 1 — receiver. Неизвестный
ключ даёт `Missing explicit interface signature`, а несовпадение слов — отдельную
ошибку. Это обязательная семантическая привязка, а не косметический name mapping.

## Поддержка и ограничения

Lowering содержит constants, locals, часть stack operations, числовую арифметику,
conversions, fields, arrays, allocation, checkcast, calls, branches, switch,
return и throw. Наличие операции в IR не включает её runtime semantics:
div/shifts/throw, например, позднее блокируются checked runtime.

Неизвестная инструкция всегда приводит к `IRValidationError` с offset.
`instanceof`, jsr/ret и ряд других распознаваемых parser-ом форм не реализованы
здесь. В основном конвейере `jsr/ret` теперь отвергаются ещё при поиске CFG leaders;
прямой вызов IRBuilder по-прежнему сообщает unsupported instruction.
`methods_from_cap` принимает ordinary concrete headers, проверяет
descriptor/linker match и не обещает поддержку abstract/native/extended methods.
Исправление D-06 устраняет ошибку вычисления extended-header offset в linker;
корректно разобранный extended method получает явный отказ adapter. Усечённый
header/body отвергается раньше на структурной стадии.

## Сопровождение и проверки

Добавляя opcode, задайте не только `Op`, но и byte length, stack types, slots,
reference tags и branch targets. Нужны негативные проверки truncated operands,
перехода в середину инструкции, underflow, max_stack overflow и несовместимого merge.
Для вызова проверяйте receiver и параметры отдельно. Для нового Descriptor-типа
обновляются nibble parser, type model и последующие stages.

При изменении координат синхронно обновляются `methods_from_cap`, `metadata_from_cap`
и `MethodIndex`; нельзя компенсировать неверный offset случайным сдвигом в одном
тесте. Контракт обработчиков от CAP metadata adapter до Soot traps проверяется в
[test_handler_pipeline.py](../../cfg_generator/tests/test_handler_pipeline.py),
границы и ошибки CFG — в
[test_exception_handlers.py](../../cfg_generator/tests/test_exception_handlers.py).
Классификация terminators, decoded conditional forms и согласование CFG/JCVM/Soot
проверяются в [test_control_flow.py](../../cfg_generator/tests/test_control_flow.py).
Проверки адаптации находятся в
[test_adapter.py](../../pysoot_adapter/tests/test_adapter.py).
Разделение structural/typed поддержки headers и координаты handlers после разбора
бинарного Method component проверяет
[test_method_headers.py](../../cap_decompile/tests/test_method_headers.py).
