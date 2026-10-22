# pysoot_adapter

Преобразует `soot_ir.Program` и метаданные CAP в настоящие Python-объекты
`pysoot.sootir`. Модуль не запускает JVM, Java Soot, `pysoot.Lifter` или angr.

Целевая ревизия pysoot:
[`16ab55db71a162efea3d44251fb93893140bbef2`](https://github.com/angr/pysoot/tree/16ab55db71a162efea3d44251fb93893140bbef2).
Адаптер проверяет поля используемых dataclass-классов. Устанавливайте зависимость
из файла, фиксирующего commit: версия `8.0.0.dev0` сама по себе не определяет
ревизию исходников.

## Установка и запуск

Из корня проекта, Python 3.10+ и Git:

```powershell
python -m pip install -r requirements-pysoot.txt
python main.py --no-png --quiet
```

`--no-png` позволяет запускать преобразования без Graphviz. Если Graphviz
установлен, можно запустить `python main.py`. Прежние этапы без pysoot запускаются
командой `python main.py --no-pysoot --no-png`.

Общий каталог результатов — `outputs/` рядом с `main.py`. `--output-root`
переопределяет **сам общий каталог**: при экспорте повторно добавлять `outputs/`
не нужно. Новый этап создаёт `outputs/pysoot_output/program.json` и пары
`method_N.json` / `method_N.txt`.

JSON — диагностический экспорт, а не входной формат существующего загрузчика
angr. Реальные объекты доступны через `AdaptedProgram.classes` и `.methods`.
Нумерация соответствует предыдущим этапам. Дополнительные объявления абстрактных
методов, если переданы вручную, идут после методов с телами.

## Вызов из Python

```python
from pysoot_adapter import PySootAdapter, metadata_from_cap

# symbols — тот же SymbolTable, который использован для SootIRBuilder.
metadata = metadata_from_cap(cap_file, symbols)
adapted = PySootAdapter().build(program, metadata)
adapted.export(output_root / "pysoot_output")
```

`metadata_from_cap` читает разобранные компоненты CAP. Парсер `Class.cap` сохраняет
смещения классов и интерфейсов относительно `info`; они сопоставляются с
`Descriptor.this_class_ref`. Порядок записей не используется как идентификатор.
AID, версия и полный упорядоченный список импортов в конфигурации должны
соответствовать CAP. В примере добавлен второй импорт `a0000000620001` версии 1.0.
Имена внешних API задаются пользователем; по индексам constant pool они не угадываются.

## Файлы

| Файл | Ответственность |
|---|---|
| `metadata.py` | Объявления классов, полей, методов, апплетов |
| `cap_metadata.py` | Извлечение объявлений и CAP-флагов |
| `backend.py` | Импорт pysoot и проверка контракта |
| `builder.py` | Преобразование значений, выражений, инструкций, графов |
| `model.py` | Объекты результата, дополнительные метаданные, экспорт |
| `tests/test_adapter.py` | Проверки с настоящим pysoot |

Поддержаны все виды узлов текущего `soot_ir`: locals, числовые/null-константы,
identity, арифметика, сравнения, cast, поля, массивы, создание объектов, четыре
режима вызова, if/goto/switch, return/throw. Неизвестные узлы дают ошибку.

## Инварианты

- Цели переходов остаются метками инструкций (`Unit.label`), а не индексами
  блоков. `basic_cfg` связывает объекты `SootBlock`.
- Как в `pysoot.soot_manager`, `basic_cfg` содержит обычные и исключительные
  рёбра. `exceptional_preds` — обращение исключительных рёбер. Обычные рёбра
  отдельно доступны в `MethodDetails.normal_successors`.
- Ссылка на поле — `(имя поля, объявляющий класс)`. Receiver вызова отделён от аргументов.
- CAP `ACC_INIT` даёт `CONSTRUCTOR` и `<init>`; внутренние вызовы конструктора
  переименовываются согласованно. Внешние конструкторы требуют привязки API.
- Флаги классов и методов преобразуются раздельно: CAP-биты `ABSTRACT` и
  `INTERFACE` отличаются от JVM-битов.
- Приведения byte/short/int, операции и условия переносятся без изменения;
  адаптер не переопределяет их семантику и не устраняет вызовы.
- Исходные CAP-offset сохраняются в `SootStmt.offset`. Для синтетических узлов
  используется `-1`; исходный `None` остаётся в `unit_origins`.

`AdaptedProgram.details[method_key]` содержит locals, source map, исходные
метки блоков/инструкций, warnings и полную таблицу traps: `[begin,end)`, handler,
тип исключения, priority, stop bit. `SootMethod.exceptions` предназначен для
объявленных throws-типов и не заменяет traps. Объявленные throws-типы из текущего
CAP не извлекаются: этот список остаётся пустым.

## Граница этапа

Адаптер представления готов. Загрузчик и исполнение в angr — следующий модуль.
Успешная конвертация не означает готовность апплета к корректному исполнению.

- `classes` содержит объявления CAP. Внешняя иерархия API не выдумывается;
  зависимости перечислены в `external_classes`, `external_methods`, `external_fields`.
- Разрешённое имя не означает наличие реализации API. Неразрешённые имена
  остаются в `unresolved_symbols`; `require_resolved_symbols()` проверяет их перед исполнением.
- `required_backend_features` перечисляет требования к будущему движку;
  `require_backend_features(supported)` отклоняет неподтверждённые возможности.
  Функции запуска движка в этом модуле ещё нет.
- `cap_virtual_dispatch` требует согласовать виртуальные вызовы/override по CAP-токенам
  и именам API. Синтетические `method_<offset>` сами по себе не задают override.
  Токены и aliases сохранены для загрузчика. Прямые ссылки на объявленные
  внутренние методы разрешаются сейчас; отсутствующая привязка унаследованного
  метода даёт ошибку.
- Traps переносятся; выполнение обработчиков, арифметику, casts, массивы и модели
  API должен реализовать/проверить движок.
- Адаптер поддерживает объявления abstract-методов без тела. Текущие
  `methods_from_cap` и linker ещё не пропускают abstract-методы через весь pipeline.
- Объявления static-полей извлекаются. Ссылки на внутренние static-поля зависят
  от upstream `ReferenceResolver`/`SymbolTable`: они должны передать owner.
  Этот модуль не угадывает потерянный объявляющий класс.

## Проверка

```powershell
python -m unittest discover -s pysoot_adapter/tests -v
```

Тесты используют реальные классы pysoot: ветвления с разными результатами,
switch с общими целями, переполнение short, вызовы, constructors, поля/массивы,
interface invoke, throw/traps, метаданные и весь pipeline на `example.cap`.
Небольшой числовой интерпретатор в тестах — независимая проверка узлов, а не
symbolic executor или тест angr.

Источники контракта:
[soot_manager.py](https://github.com/angr/pysoot/blob/16ab55db71a162efea3d44251fb93893140bbef2/pysoot/soot_manager.py),
[sootir](https://github.com/angr/pysoot/tree/16ab55db71a162efea3d44251fb93893140bbef2/pysoot/sootir),
[Java Card VM 3.0.5, разделы 6.9 и 6.14](https://docs.oracle.com/cd/E59935_01/JCVMS.pdf).
