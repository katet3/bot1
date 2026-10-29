# pysoot_adapter — реальные Soot-объекты и CAP-метаданные

[К документации](../README.md) · [Построитель](../../pysoot_adapter/builder.py)

## Назначение

`PySootAdapter().build(program, metadata)` принимает `soot_ir.Program` и
`ProgramMetadata`, возвращает `AdaptedProgram`. Его classes/methods содержат
настоящие `pysoot.sootir` dataclasses. Это необходимо для совместимости с CLE
и angr Soot engine; собственные похожие Python-объекты не заменяют этот контракт.

Здесь не запускается `Lifter`, JVM или Java Soot. Metadata отделены от тела,
поскольку методы сами по себе не определяют class hierarchy, fields, attrs,
CAP tokens, install AID и virtual aliases.

## Модули

| Файл | Определения | Обязанность |
| --- | --- | --- |
| `backend.py` | `load_backend`, `CONTRACT`, `PYSOOT_REVISION` | Ленивый импорт pysoot и проверка dataclass ABI |
| `metadata.py` | `FieldMetadata`, `MethodMetadata`, `ClassMetadata`, `AppletMetadata`, `ProgramMetadata` | Декларативный контракт, независимый от binary parser |
| `cap_metadata.py` | `metadata_from_cap`, `_attrs` | Join Class/Descriptor и перевод CAP flags/refs в декларации |
| `builder.py` | `PySootAdapter`, `_ProgramBuilder` | Преобразование Values/Expr/Units, проверки деклараций, классы и CFG |
| `model.py` | `MethodDetails`, `AdaptedProgram`, `_node` | Side metadata и диагностические JSON/text exports |
| `errors.py` | `AdapterError`, `DependencyError` | Ошибка входного контракта либо зависимости |
| `__init__.py` | Реэкспорты | Фасад adapter, metadata и результирующие типы |
| `tests/test_adapter.py` | `AdapterTests`, `CAPIntegrationTests`, helpers | 19 регрессий; подробнее в руководстве по тестам |

## Контракт зависимости

Целевая ревизия pysoot — `16ab55db71a162efea3d44251fb93893140bbef2`.
`load_backend` сравнивает состав и порядок dataclass fields для value/expression/
statement/block/method/class. Проверка учитывает inherited fields и выполняется
до создания объектов. Она проверяет структурную совместимость; происхождение
установленного кода по Git cryptographically не подтверждается этим guard-ом.
Для воспроизводимости используется VCS pin в `requirements-pysoot.txt`.

Загрузка кэшируется. Если dependency отсутствует или структура отличается,
выдаётся явная подсказка установки, а не fallback к устаревшему пакету с PyPI.

## CAP metadata

`metadata_from_cap` сверяет собственные AID/version и **порядок** imports с
SymbolTable. Class и Descriptor объединяются по info-relative class offset.
Проверяются согласие interface flags, список interfaces, field ownership и
static flags. CAP access bits переводятся отдельными таблицами; они не равны
универсально JVM access flags.

Конструкторы получают `<init>`, void return и соответствующие attrs. Для обычных
не-static/non-private/non-constructor методов создаются aliases тэгов 3/4 с CAP
virtual token. Private token 255 не является уникальным идентификатором всех
методов; concrete method key использует offset. Applet metadata содержит настоящий
AID из Applet component и ключ install.

Внешние иерархии в CAP отсутствуют и не придумываются. Они перечисляются как
external classes и при необходимости должны быть явно добавлены runtime profile.

## Конвертация программы

Сначала индексируются class/field/method declarations и aliases. Проверяются
дубли классов, полей, signatures, keys и conflicting aliases. Затем каждое тело
валидируется и сопоставляется с declaration. Отсутствие тела concrete метода —
ошибка. Abstract declaration может быть представлена без тела, если metadata
пришли от поддержанного источника; это не устраняет ограничения CAP linker.

`Value` становится соответствующим SootLocal/constant/this/param/caught ref.
`Expr` — SootBinop/Cast/Field/Array/New/Invoke и т.д. Target label сохраняется.
Synthetic CAP offset `None` записывается в pysoot statement как `-1`, а точное
`None` сохраняется в side metadata.

`SootMethod.basic_cfg` включает normal и exceptional successors, как ожидает
контракт pysoot. Отдельный `MethodDetails.normal_successors` сохраняет нормальный
граф; `exceptional_preds` хранит обратные исключительные связи. Эти структуры
нельзя взаимозаменять при анализе.

## AdaptedProgram и экспорт

| Поле/метод | Назначение |
| --- | --- |
| `classes` | Имя класса → SootClass |
| `methods` | Устойчивый CAP key → SootMethod |
| `details` | CAP source map, ordered traps, origins и features |
| `metadata` | Полный набор переданных деклараций |
| `external_methods/fields/classes` | Внешние зависимости без выдуманных тел |
| `unresolved_symbols` | Отсутствующие привязки имён/идентичностей |
| `required_backend_features` | Объединение требований тел плюс CAP virtual dispatch |
| `require_resolved_symbols()` | Явная проверка полноты name bindings |
| `require_backend_features(supported)` | Проверка заданного набора возможностей backend-а |
| `export(output_dir)` | Диагностический program.json и отдельные method files |

Схема JSON: `cap2soot.pysoot_adapter.program/1`. Это представление для диагностики,
не pickle и не обещанный формат восстановления `AdaptedProgram`. Loader принимает
объект из builder, не путь к этому JSON. `backend_version` и `target_revision`
сохраняются для отчётности.

## Сопровождение

При обновлении pysoot сначала сравните CONTRACT и семантику CFG/targets; простое
совпадение имён классов недостаточно. При новом statement добавляются conversion,
source validation и проверка реального узла. При изменении деклараций проверяйте
наследование, одинаковые имена полей у разных owners, constructor attrs,
virtual aliases и missing concrete bodies.

Adapter не должен сам чинить конфликтующие signatures, создавать отсутствующие
external bodies или запускать static initialization. Такие действия делают
диагностическую трансляцию неотличимой от недоказанной модели поведения.
Регрессии: `python -m unittest pysoot_adapter.tests.test_adapter -v`.
