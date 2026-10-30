# Как найти вход, достигающий name1.java:66

Пример проверен на репозитории `katet3/bot1`, commit
`e6d944f4f335070b8603880f66c9697a2a3e49bf`, 29 октября 2026 года.
Python 3.12 / angr 10.0.4.post1, Linux. Команды ниже приведены для используемого
в проекте Windows-окружения; отдельный прогон Windows не выполнялся.

## 1. Что именно ищем

В `examples/name1/name1.java` строка 66:

```java
setDesKey(apdu, len);
```

До неё код выполняет `selectingApplet()`, получает APDU buffer и первый chunk
данных, затем выбирает ветвь по INS. Условие достижения вызова:

```text
Апплет установлен, process вызван в корректном APDU-контексте;
selectingApplet() == false;
INS == 0x20.
```

При нормальном выполнении APDU API **CLA, P1, P2, содержимое данных и len не
добавляют условий для достижения самой строки 66**. Проверки P1/len идут внутри
вызываемого метода. Поэтому APDU может достигнуть строки 66 и затем завершиться
ошибкой `6700` или `6A86`.

Успешное завершение установки ключа требует отдельно:

```text
(P1 == 0x01 и len == 16) или (P1 == 0x02 и len == 24).
```

`len` здесь — результат первого `setIncomingAndReceive()`, а не автоматически
весь Lc. В harness по умолчанию принимаются все данные, но можно задать частичный
приём. `selectingApplet` — контекст JCRE, а не ещё один байт APDU; значение задаётся
отдельным флагом модели.

## 2. Подготовка и запуск

Распакуйте `name1_line66_example.zip` в корень проекта, где расположен `main.py`.
Существующие файлы реализации не заменяются; добавляются пример, это руководство
и сохранённый пример JSON-отчёта.

Если необходимые зависимости ещё не установлены:

```powershell
.\.venv-angr10\Scripts\python.exe -m pip install -r requirements-javacard.txt
```

Запустите поиск с 24 байтами данных:

```powershell
.\.venv-angr10\Scripts\python.exe find_name1_line66.py
```

Скрипт исполняет настоящий install/constructor, затем создаёт **символические**
CLA, INS, P1, P2 и каждый байт DATA. INS заранее не фиксируется. Количество данных
в этом запуске конкретное: Lc=24, первый приём=24. Затем angr ищет вход в setDesKey
и решатель получает допустимые входы из реальных ветвлений CAP.

Существенный результат:

```text
Java line 66: reached
CAP callsite: process offset 36, Unit 27
Condition: INS == 0x20; CLA/P1/P2/DATA unrestricted
Constraints: ['<Bool SignExt(24, INS) == 0x20>']
Continuation from setDesKey entry:
  SW=6700; P1=01
  SW=6A86; P1=254 values (see JSON)
  SW=9000; P1=02
Continuation errors=0; active=0
```

`SignExt(24, INS)` расширяет 8-битное значение до 32 бит для Soot. Это не означает
24-байтовый INS. Единственное допустимое INS остаётся `0x20`.

Отчёт записывается в `outputs/name1_line66/result.json`. Иной путь задаётся
`--output outputs/my_run/result.json`. Сохранённый результат нашего запуска
поставляется отдельно как `examples/name1/line66_result.example.json`.

## 3. Как читать найденный APDU

В коротком входном APDU байты идут как `CLA INS P1 P2 Lc DATA...`.
Один из найденных входов для достижения строки имеет `P1=0`: вызов достигается,
а внутри него затем получается `6A86`. Для успешного завершения скрипт отдельно
печатает `Successful APDU` с `P1=2`.

Простой успешный тестовый вход:

```python
apdu = bytes.fromhex("00 20 02 00 18") + bytes(24)
```

Это CLA=00, INS=20, P1=02, P2=00, Lc=0x18=24 и 24 нулевых байта данных.
Нули — один возможный solver witness, а не требование программы к ключу.
Скрипт извлекает **весь пакет одним решением** через Concat, чтобы байты примера
были совместимы с одним и тем же путём.

Для длины 24 ожидаются следующие множества P1:

| P1 | Строка 66 достигнута? | После выполнения setDesKey |
| --- | --- | --- |
| `0x02` | Да | `9000`, ключ записан |
| `0x01` | Да | `6700`, ожидались 16 принятых байт |
| Любое из остальных 254 значений | Да | `6A86` |

## 4. Другие варианты запуска

16 байт: успешная ветвь станет `P1=1`:

```powershell
.\.venv-angr10\Scripts\python.exe find_name1_line66.py --length 16 --output outputs/name1_line66_len16/result.json
```

Частичный приём 8 из 24 байт: строка достигается при INS=20, но при P1=1/2
метод выдаёт `6700`:

```powershell
.\.venv-angr10\Scripts\python.exe find_name1_line66.py --length 24 --receive-length 8 --output outputs/name1_line66_partial/result.json
```

Контекст выбора апплета: process возвращается до switch, поэтому строка 66
не достижима в этом контексте:

```powershell
.\.venv-angr10\Scripts\python.exe find_name1_line66.py --selecting --output outputs/name1_line66_select/result.json
```

Длина и receive_length в текущем API конкретные, не свободные символические
переменные. Их можно менять отдельными запусками в пределах 0..255. Флаг selecting
также конкретный. Скрипт не заявляет анализ произвольного symbolic Lc или всех JCRE
состояний одновременно.

## 5. Главное в Python-коде

Следующий фрагмент показывает механизм. Полная исполняемая версия —
`find_name1_line66.py`, с проверками результата и отчётом.

```python
from angr import claripy
from angr_integration.name1_demo import load_name1
from angr_integration.javacard_session import JavaCardSession

loaded = load_name1()
session = JavaCardSession(loaded)
session.install()

ins = claripy.BVS("INS", 8, explicit_name=True)
p1 = claripy.BVS("P1", 8, explicit_name=True)
state = session.prepare_command(ins, p1=p1, data=bytes(24), selecting=False)

key = loaded.index.by_signature[
    ("name1.name1", "setDesKey", ("javacard.framework.APDU", "short"))
]
target = loaded.method_address(key)
simgr = loaded.project.factory.simgr(state)
simgr.explore(find=lambda s: s.addr == target, n=200)

if not simgr.found:
    raise RuntimeError("Цель не найдена: проверьте active/errored и бюджет")
found = simgr.found[0]
print(found.solver.constraints)
print(found.solver.eval_upto(ins, 257))  # [32], то есть 0x20
```

В кратком фрагменте символические только INS/P1; в полном скрипте — также
CLA/P2/DATA. `session.run(found.copy())` продолжает найденное состояние до исходов
команды. Тогда можно отдельно выбрать `SW=9000` и получить успешный APDU.

## 6. Как строка Java соотнесена с адресом CAP

В проекте нет универсального `--find-line 66`. Число 66 нельзя передать angr как
машинный адрес или CAP-offset. Для этой неизменённой фикстуры исходник/JCA и CAP
дают такое соответствие:

| Уровень | Цель |
| --- | --- |
| Java source | `name1.java:66`, вызов setDesKey |
| Caller CAP key | `112233445566@1.0:internal:t6:o76`, process |
| Instruction в process | Method-local CAP offset 36 |
| Soot callsite | Unit 27, block 5, statement 4 |
| Callee key | `112233445566@1.0:internal:t6:o142`, setDesKey |
| Найденный адрес | `<name1.name1.setDesKey(javacard.framework.APDU, short)+(0:0)>` |

Поиск остановлен на входе вызываемого метода: это доказывает, что вызов со строки
66 уже выбран и выполнен переход в него. Callsite находится внутри Soot block,
поэтому обычная block-wise exploration могла бы пропустить остановку ровно перед
Unit 27. Использование callee entry устраняет эту неоднозначность для единственного
вызова process → setDesKey. Скрипт проверяет hash исходного CAP и уникальность
этого callsite; при изменении исходников mapping нужно пересмотреть.

## 7. Что проверено и чего отчёт не утверждает

Для найденного состояния проверены обе стороны эквивалентности условию INS=20
в фиксированном контексте запуска. Одного witness было бы недостаточно: он
доказывает наличие решения, но не полноту ограничения.

Первый explore останавливается после нахождения цели. В его search.active могут
оставаться ветви других INS: это не результат полного исследования всех команд.
Отдельный after_call исследует только продолжение найденного вызова и содержит
собственные active/errors. При нехватке бюджета отсутствие found не объявляется
недостижимостью. Проверен и такой запуск с `--max-steps 1`.

Проверены длины 0, 16, 24, 255, частичный приём, selecting=true и replay найденного
успешного APDU: команда вернула `9000`. Исходные модули проекта не менялись.
`main.py` остаётся конвейером преобразования/загрузки; символьный поиск в этом
примере запускает предоставленный отдельный script.
