# Загрузчик angr

`AngrLoader` принимает `pysoot_adapter.AdaptedProgram` и создаёт настоящий
`angr.Project` с архитектурой `ArchSoot`, Java VM memory и Soot engine.
Готовые классы передаются в CLE напрямую. Java, JAR, `pysoot.Lifter` и повторный
разбор CAP для этого этапа не нужны.

Загрузка программы и исполнение апплета — отдельные операции. `main.py`
выполняет загрузку и экспорт отчёта. Он не вызывает `install`, `process`
или исследование путей.

## Установка и запуск

Проверенные версии: Python 3.12, angr 10.0.4.post1, CLE и archinfo 10.0.4,
pysoot из revision, указанного в `requirements-pysoot.txt`.
angr 10 требует **Python >= 3.12**. Проверка выполнена на Linux; запуск на
Windows в этой среде не проверялся. Для изоляции зависимостей удобно создать
новое виртуальное окружение. На Windows из корня проекта:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-angr.txt
.\.venv\Scripts\python.exe main.py --no-png --quiet
```

Для установки pysoot по Git-ссылке нужен Git в PATH. Если уже используется
подходящее окружение:

```shell
python -m pip install -r requirements-angr.txt
python main.py --no-png --quiet
```

Результаты нового этапа:

| Файл | Содержание |
| --- | --- |
| `outputs/angr_output/load_report.json` | Версии, входной метод, классы, методы, внешние ссылки, ограничения исполнения |
| `outputs/angr_output/load_report.txt` | Читаемый отчёт |
| `outputs/angr_output/addresses.json` | Соответствие адресов angr, Unit labels и смещений CAP |

`--output-root` уже обозначает общий каталог результатов. Например,
`--output-root results` создаёт `results/angr_output`, без дополнительного `outputs`.
`--no-angr` завершает конвейер на pysoot, `--no-pysoot` — на Soot IR.
Зависимости angr импортируются только при загрузке нового этапа.

В проверенной сборке angr при импорте без необязательного Unicorn может появиться
сообщение `unicorn support disabled`. Оно относится к исполнению машинного кода;
данный загрузчик использует Soot и не включает Unicorn/JNI.

## Программный API

```python
from angr_integration import AngrLoader, SymbolicArgument

# adapted_program — результат PySootAdapter.build(...).
loaded = AngrLoader().load(adapted_program, entry_key=method_key)
project = loaded.project
address = loaded.method_address(method_key)
loaded.export(output_root / "angr_output")

# Для метода, входящего в проверенный профиль исполнения:
state = loaded.create_call_state(method_key, args=[SymbolicArgument("x")])
simgr = project.factory.simgr(state)
simgr.run(n=100)
# Оценивайте также simgr.errored и simgr.active: лимит шагов не означает завершения.
```

`method_key` — точный ключ из `pysoot_output/program.json`, например
`7c0f1b01883c@1.0:internal:t6:o191`. Число после `o` обозначает смещение заголовка
метода в Method component; локальные смещения инструкций отсчитываются отдельно.
Токены методов могут повторяться, поэтому выбор только по токену не используется.

Если `entry_key` не задан, загрузчик выбирает единственный install-метод из
метаданных Applet component. Для программы без Applet component допустим
единственный конкретный метод. При неоднозначности `project.entry` остаётся
`None`: нужно указать ключ. Переопределение из CLI:

```shell
python main.py --no-png --quiet --angr-entry "7c0f1b01883c@1.0:internal:t6:o191"
```

Эта команда меняет точку входа загруженного проекта и не запускает метод.

### Адреса и происхождение инструкций

```python
address = loaded.address_for_label(method_key, label)
location = loaded.source_location(address)
addresses = loaded.addresses_for_offset(method_key, cap_offset)
```

Адрес angr содержит **дескриптор метода, индекс блока, индекс statement внутри
блока**. Он не равен ни Unit label, ни смещению CAP. Одно смещение CAP может
соответствовать нескольким statements после lowering. Для синтетических
statements `SourceLocation.cap_offset` равен `None`.

### Начальное состояние

`create_call_state` подготавливает прямой вызов и адрес возврата `SootAddressTerminator`.
Фактические параметры передаются отдельно от `this`. Поддерживаются числовые
параметры `byte`, `short`, `int`, `boolean`: Python-числа в диапазоне типа,
`SymbolicArgument(name)` или bitvector шириной 8/16/32/1 соответственно.
Отрицательные byte/short расширяются со знаком до 32 бит представления Soot;
boolean расширяется нулями. Исходные bitvectors доступны в
`state.globals["cap2soot.inputs"]` в порядке параметров.

Для instance-метода нужны явно переданные `receiver` типа `SimSootValue_ThisRef`
и `base_state` того же проекта с его heap. Пока допускается точный тип
объявляющего класса. `base_state` копируется. Начальное состояние не создаёт
фиктивные APDU/OwnerPIN, не вызывает конструктор и не восстанавливает
персистентное состояние апплета. Состояние реальной карты — следующий модуль.

## Граница исполнения

В CLE загружаются все классы и методы адаптера, включая тела с внешними вызовами.
Ссылки, объявления и таблицы исключений сохраняются в `loaded.program`.
Поля `loaded: true` и `execution_ready` в отчёте имеют разный смысл.

Для проверки загрузчика разрешён ограниченный профиль: локальные переменные,
целочисленные константы, add/sub/mul/and/or/xor, знаковые сравнения, ветвления,
switch с локальным ключом, преобразования в byte/short/int через locals, возвраты и внутренние
статические вызовы. Перед созданием состояния проверяются также вызываемые
статические методы. Преобразование произвольного числа в boolean не включено.
Эта проверка консервативна: учитываются и недостижимые при
конкретном входе участки метода.

Пока не включены heap/массивы/поля, reference casts, instance dispatch по CAP-токенам,
Java Card API, `<clinit>`, исключения, JNI, деление/остаток, сдвиги и unary-neg.
Часть операций присутствует в angr, но её корректность для нашего Java Card
pipeline ещё не установлена. Загрузчик сообщает об этих ограничениях и
отказывается выдавать состояние для такого метода. Поддерживаемый профиль
не означает полноты анализа, гарантированного завершения или доказательства
отсутствия ошибок.

`CheckedSootEngine` использует существующие семантики angr; он не реализует
собственный symbolic executor. Небольшая адаптация сохраняет ошибки в
`SimulationManager.errored` вместо пропуска statement и запрещает автоматический
`unconstrained`-ответ неизвестного метода. Автоматические SimProcedures отключены.
Модели Java Card API будут подключаться явно на следующем этапе.

`CAPSimOS` создаёт Java-кадры вызова без desktop `System.in/out` и без скрытого
исполнения инициализаторов. Не изменяйте `use_sim_procedures`, engine или
внутренние объекты уже загруженного проекта: это меняет проверенный контракт.

## Проверка

```shell
python -m unittest discover -s pysoot_adapter/tests -v
python -m unittest discover -s angr_integration/tests -v
python -m angr_integration.demo
```

Демо исполняет синтетический `static int sign(short x)` через настоящий angr.
Оно получает два завершённых пути (`-7` и `7`), ограничения и конкретный пример
входа для каждого пути. Файлы записываются в `outputs/angr_demo`. Это проверка
интеграции, а не исполнение `example.cap`.

Тесты дополнительно проверяют отрицательные значения, narrow casts и переполнение
short, вызов и возврат между методами, switch с общей целью, ограничение шагов,
диагностику неизвестных методов, сохранение exception metadata, копирование
base_state и загрузку всего тестового CAP. Фактический протокол — `TEST_RESULTS.txt`.

## Файлы модуля

| Файл | Ответственность |
| --- | --- |
| `loader.py` | Публичный API, сборка Project, отчёт |
| `backend.py` | CLE backend над уже готовыми объектами |
| `index.py` | Ключи методов, адреса, смещения CAP |
| `state.py` | Типизированные аргументы и состояние прямого вызова |
| `runtime.py` | Адаптация SimJavaVM и обработка ошибок Soot engine |
| `readiness.py` | Проверка поддерживаемого профиля исполнения |
| `dependencies.py`, `errors.py` | Совместимость версий и ошибки |
| `demo.py`, `tests/test_loader.py` | Исполняемый пример и интеграционные проверки |

Контракты сверены с исходниками
[CLE Soot](https://github.com/angr/cle/blob/v10.0.4/cle/backends/java/soot.py),
[SimJavaVM](https://github.com/angr/angr/blob/v10.0.4.post1/angr/simos/javavm.py) и
[Soot engine](https://github.com/angr/angr/blob/v10.0.4.post1/angr/engines/soot/engine.py).

