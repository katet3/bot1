# soot_ir — типизированные Jimple-подобные тела

[К документации](../README.md) · [Построитель](../../soot_ir/builder.py)

## Назначение и внешние контракты

`SootIRBuilder(symbols).build_program(methods)` преобразует все JVM-like методы
в `Program`. `build(method)` подходит только тогда, когда отсутствуют ссылки на
непереданные внутренние тела. Вход может быть моделью или поддерживаемым JSON/dict
через `input.read_method`; перед lowering проходит source validation.

Этот пакет не импортирует Java Soot и не запускает JVM. Он создаёт собственную
dataclass-модель, проверяет её и экспортирует JSON и читаемый `.jimple`.
Следующий `pysoot_adapter` отвечает за реальные классы библиотеки pysoot.

## Модули

| Файл | Определения | Обязанность |
| --- | --- | --- |
| `model.py` | `Local`, `Value`, `MethodRef`, `FieldRef`, `Expr`, `Unit`, `Block`, `Trap`, `Method`, `Program` | Сериализуемый контракт тел и символов |
| `builder.py` | `SootIRBuilder`, `_MethodBuilder`, `backend_features`, `make_blocks` | Пролог, expressions/Units, мосты, traps и block graph |
| `symbols.py` | `package_key`, `reference_key`, `SymbolTable` | Устойчивые идентичности, привязки Java-имён и типов |
| `input.py` | `LoweringError`, `plain`, `read_method`, `kind`, `stack_kind`, `op_name`, `terminator_kind` | Нормализация входного представления |
| `source_validation.py` | `validate_source` | Проверка JSON/dict до построения; не доверяет внешнему дампу |
| `reference_types.py` | `infer_reference_types` | Консервативное объединение reference types для slots/values |
| `validation.py` | `validate` | Локалы, типы, control flow, definite assignment и traps результата |
| `text.py` | `render`, `method_text` | Читаемое представление Units |
| `__main__.py` | `main` | JVM-like JSON → Soot JSON/Jimple CLI |
| `__init__.py` | Реэкспорты | Публичный builder, symbols и модели |

## Формат результата

`Program.schema = cap2soot.soot_ir.program/1`,
`Method.schema = cap2soot.soot_ir.method/1`. `Unit.label` — сквозной номер в теле;
`Block.index` — индекс блока; `Block.label` — label первой инструкции блока.
Successors в Block — **индексы блоков**, targets в Unit — **labels**.

Unit хранит kind, left/right, target/cases/default, CAP offset, source block,
source statement и handlers. Expr описывает операции и ссылки на MethodRef/FieldRef.
Source map — offset → последовательность labels, включая пустую для устранённых
операций. Synthetic units могут иметь `offset=None`.

`Trap` задаёт half-open диапазон Units `[begin, end)`, handler label, exception
type, priority и stop bit. Факт его присутствия добавляет обязанность backend-а
`ordered_exception_dispatch`; создание Trap не означает поддержку исполнения.

## Решения lowering

**Числа.** Значения short/byte вычисляются через Soot int32, но narrowing явно
вставлен в нужные места. Например, short overflow восстанавливается cast в short
и расширением в int. Cast operand материализуется в local, поскольку выбранный
angr cast handler ожидает local. Динамический numeric→boolean без доказательства
0/1 отклоняется. У сдвига величина маскируется 31; runtime поддержка проверяется
отдельно.

**Параметры блоков.** Для ребра с аргументами создаётся bridge. Сначала сохраняются
все источники, затем назначаются параметры цели. Так операция `p0,p1 := p1,p0`
не превращается в последовательную запись с потерей старого значения.

**Identity/prologue.** Receiver и параметры получают `@this`/`@parameter`, затем
переносятся в локальные слоты. Param index и slot index не смешиваются.

**References.** Консервативный inference соединяет несовпадающие типы в Object.
Для `array_length` нужен доказанный array type: Object[] не является общим
родителем primitive arrays. При потере точного типа операция отклоняется,
а не исправляется заведомо неверным cast.

**Исключения.** Сохраняются protected regions и порядок handlers, создаются
exception bridges с caught_exception identity. Это данные для будущего dispatch;
checked runtime пока отказывается исполнять методы с traps.

## Символы и целостность программы

`symbols.json` задаёт package AID/version, упорядоченные imports, class/method/field
names, catch_types и ранние interface_signatures. Тип reference содержит encoded
class_ref: high bit указывает external class, package token индексирует imports.
Изменение порядка imports меняет смысл ссылок, даже если набор пакетов тот же.

При отсутствии external name строится диагностическое синтетическое имя и
добавляется unresolved key. Внутренние классы/поля могут использовать устойчивые
синтетические имена. `Program.require_resolved_symbols()` доступен отдельно;
сам `build_program` допускает диагностический результат с unresolved symbols.

Методы регистрируются до преобразования тел. Проверяются дубли identities и
Soot signatures, static/special mode и совпадение подписи внутреннего вызова.
Внутреннему static field недостаточно одного смещения: без владельца field_ref
отклоняется. API-поведение не содержится в SymbolTable.

## Обязательства backend-а

`backend_features` собирает `unit_label_targets`, числовые semantics, casts,
arrays, calls и exception dispatch. Список описывает, **что требуется**, а не
что уже реализовано в angr. Adapter пересчитывает его по Units и добавляет
CAP virtual dispatch при наличии соответствующих деклараций.

## CLI

После главного запуска, сохранившего JVM-like IR:

```powershell
.\.venv-angr10\Scripts\python.exe -m soot_ir outputs/name1/jvm_ir_output --symbols examples/name1/symbols.json --output outputs/name1_soot_rebuilt
```

Принимается один JSON или каталог `method_*.json`. Пустой вход и output,
накрывающий входные файлы, отклоняются. У директории используется сортировка
имён файлов; `method_N` всё равно не является устойчивым CAP-ключом.

## Сопровождение и тесты

При новой операции согласуйте source validation, lowering, validation результата,
feature obligations и pysoot conversion. При изменении merge/copy проверяйте
back-edge swap и сохранение эффектов. При изменении numeric semantics проверяйте
отрицательные operands, narrowing, overflow и signed comparison, а не только
положительные константы.

Нельзя объявлять full Shimple/SSA по отсутствию стека. Нет общего Java compiler
round-trip и обратного import из диагностического pysoot JSON. Проверки данной
стадии сейчас включены в adapter/integration suites; расширение instruction set
требует регрессии на всех последующих уровнях.
