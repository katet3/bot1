# Java Card runtime — API-модели и последовательности APDU

[К документации](../README.md) · [angr integration](angr_integration.md)

## Границы профиля

`Name1API` — explicit profile `name1-jc304-subset-v1`. Он моделирует только
контракты, необходимые исходному `name1.cap`: Applet lifecycle, короткий APDU,
ISOException на границе команды, операции транзакций, arrayCopy и DES.
Это Python-модели с состоянием, а не вызов предоставленных native C-функций.
Нет общего JCRE dispatcher, firewall, GlobalPlatform, PIN или power-loss model.

Профиль активируется через `AngrLoader.load(..., api_profile='name1')`.
Он добавляет explicit class declarations и таблицу моделей. Конфликт с CAP
declaration не разрешается молча. PyCryptodome проверяется при создании профиля;
зависимость необязательна для загрузки без API.

## Исходные модули и API

| Файл | Определения | Ответственность |
| --- | --- | --- |
| `angr_integration/javacard_api.py` | `APIModel`, `DESKeyState`, `CipherState`, `ISOExit`, `JavaCardState`, `Name1API`, `integer`, `byte_values`, `des_crypt` | Привязки, state plugin и bounded API semantics |
| `angr_integration/javacard_session.py` | `CommandFault`, `CommandRun`, `JavaCardSession` | Установка, подготовка команд, запуск, сохранение/выбор пути |
| `angr_integration/name1_demo.py` | `load_name1`, `run_demo`, `main`, fixture constants | Полный pipeline и регрессионный сценарий оригинального CAP |
| `angr_integration/tests/test_javacard.py` | `JavaCardTests` | 20 тестов lifecycle, APDU, crypto, transactions и ошибок |
| `requirements-javacard.txt` | requirements chain и `pycryptodome==4.1.0` | Воспроизводимая зависимость concrete DES |

## Таблица 17 API-моделей

Все ключи ниже имеют package version `1.5`. FW = `a0000000620101`,
SEC = `a0000000620102`, CRYPTO = `a0000000620201`.
Полный ключ строится как `AID@1.5:суффикс`. Аргумент receiver в params не включён.

| Пакет / суффикс | Java method | Handler / эффект |
| --- | --- | --- |
| FW `c3:t6:m0` | `Applet.<init>()` | `applet_init`: отметка constructed только во время install |
| FW `c3:t3:m2` | `Applet.register(byte[],short,byte)` | `register`: единственная регистрация AID длиной 5..16 |
| FW `c3:t3:m3` | `Applet.selectingApplet()` | `selecting`: явно заданный harness-ом флаг |
| FW `c10:t3:m1` | `APDU.getBuffer()` | `get_buffer`: один текущий buffer reference |
| FW `c10:t3:m6` | `APDU.setIncomingAndReceive()` | `receive`: копирует первый chunk, возвращает его длину |
| FW `c10:t3:m8` | `APDU.setOutgoingAndSend(short,short)` | `send`: сохраняет response slice |
| FW `c7:t6:m1` | `ISOException.throwIt(short)` | `throw_iso`: передаёт SW через ISOExit |
| FW `c8:t6:m1` | `JCSystem.beginTransaction()` | `begin`: persistent snapshot |
| FW `c8:t6:m2` | `JCSystem.commitTransaction()` | `commit`: завершение транзакции |
| FW `c8:t6:m18` | `JCSystem.requestObjectDeletion()` | `request_deletion`: флаг запроса; GC не исполняется |
| FW `c16:t6:m1` | `Util.arrayCopy(byte[],short,byte[],short,short)` | `array_copy`: overlap-safe copy, возвращает destOffset+length |
| SEC `c13:t6:m0` | `KeyBuilder.buildKey(byte,short,boolean)` | `build_key`: модель transient DESKey |
| SEC `c10:t1:m5` | `DESKey.setKey(byte[],short)` | `set_key`: копирует материал, увеличивает версию ключа |
| CRYPTO `c1:t6:m0` | `Cipher.getInstance(byte,boolean)` | `cipher_instance`: конкретная модель Cipher |
| CRYPTO `c1:t3:m3` | `Cipher.init(Key,byte)` | `cipher_init`: default zero IV |
| CRYPTO `c1:t3:m4` | `Cipher.init(Key,byte,byte[],short,short)` | `cipher_init`: explicit CBC IV |
| CRYPTO `c1:t3:m1` | `Cipher.doFinal(byte[],short,short,byte[],short)` | `cipher_final`: concrete crypto и запись результата |

`lookup(ref)` сверяет key, owner, name, params, return и static flag.
`accepts_receiver` разрешает APDU только для точного APDU type, DESKey — только
для `cap2soot.api.TransientDESKey`, Cipher — для `cap2soot.api.DESCipher`.
Одной декларации класса с похожими методами недостаточно: state записи ключа/
шифра должны быть созданы соответствующей API-моделью.

## Состояние JavaCardState

Plugin хранит installing/constructed/registrations, selecting, текущие apdu/buffer,
incoming и receive_length, received/sent, response/status/exception, keys/ciphers,
transaction snapshot, transient arrays/global references и events.
Объектные поля апплета остаются в CAPHeap. Ключевой материал и параметры cipher
лежат в immutable dataclasses в plugin и заменяются целиком при изменении.

При `state.copy` словари копируются, остальные значения неизменяемы. Plugin
не допускает merge/widen. `events` — диагностический tuple, не журнал для replay
физической карты. Его очистка на новой APDU не уничтожает persistent heap.

## JavaCardSession: lifecycle и методы

| Метод | Поведение |
| --- | --- |
| `__init__(loaded)` | Требует API-профиль и ровно один applet в metadata |
| `install(max_steps=500)` | Выполняет настоящий CAP install, проверяет регистрацию, сохраняет состояние |
| `prepare_command(ins,p1=0,p2=0,data=b'',cla=0,selecting=False,receive_length=None)` | Создаёт новое состояние команды без запуска |
| `run(state,max_steps=500)` | Исследует пути, возвращает CommandRun |
| `transmit(...,max_steps=500)` | prepare+run; автоматически сохраняет только единственный полностью завершённый исход |
| `choose(completed_state)` | Явно копирует выбранное завершённое состояние того же project |

Install array кодируется как `[aid_length] + aid + [0,0]`: пустые control-info
и applet-data. Выбор install data не является универсальной схемой конфигурации
любого апплета. Process ищется по `(receiver.type, 'process', ('javacard.framework.APDU',))`;
следовательно, корректная name binding `process` нужна harness-у.

На новую APDU создаются свежие Java frames, затем копируются CAPHeap/JavaCardState
и solver constraints. Переиспользовать старый завершённый frame нельзя: после
ISOException он может содержать `Ijk_Exit` и оставшиеся кадры. Heap хранит изменения
выбранной предыдущей команды, поэтому sequence действительно stateful.

APDU object/buffer выделяются один раз. Весь buffer на 260 байт очищается, header
занимает offsets 0..4 (`CLA INS P1 P2 Lc`), первый data chunk начинается с 5.
Исходный data length ≤255; receive_length лежит в диапазоне 0..len(data).
Значение Lc отражает полный переданный вход, а return setIncomingAndReceive —
первый принятый chunk. Повторный receive либо receive после send отклоняются.
Ссылка APDU/buffer не может быть записана в поля/массивы как обычная persistent ref.

## Результаты, ветвление и ошибки

`CommandRun` содержит tuples `completed`, `errored`, `active`.
Нормальный return без незакрытой транзакции получает `9000`, если SW ещё не задан.
`ISOExit` немедленно завершает команду со статусом и отметкой ISOException.
Java catch handlers не вызываются. Другие Java/API faults представлены diagnostics,
без произвольно выбранного SW.

`summary()` сериализует SW, concrete response bytes, source errors и active count.
Если SW/response остаются многозначными, строгие `integer/byte_values` не выбирают
witness автоматически. Для общего символического ответа анализируйте сами BV
в состояниях и constraints, а формат отчёта расширяйте отдельно.

Наличие одного successful path недостаточно при остальных errored/active.
`transmit` в таком случае не меняет session.state. При нескольких completed
клиент может исследовать каждый, сохранить отдельные сессии либо вызвать choose.
`choose` проверяет project/plugin/terminator/status, но не является механизмом
аутентификации происхождения состояния среди нескольких сессий одного project:
клиент должен выбирать результат своей команды.

## Транзакции

`begin()` сохраняет значения всех instance fields и нетранзиентных массивов.
`commit()` удаляет snapshot; `abort()` восстанавливает его. Вложенный begin,
commit/abort без транзакции и allocation при активной транзакции дают диагностику.
Буфер APDU и transient key material не откатываются. `Util.arrayCopy` проверяет
оба диапазона до записи, поэтому ошибка не оставляет частично записанный результат.

При deadended state с открытой транзакцией session выполняет abort. Если это
обычный return, добавляется `CommandFault(uncommitted_transaction)` вместо
completed `9000`. При ISOException SW сохраняется после rollback. Произвольные
engine errors не проходят этот deadended cleanup: профиль не заявляет полную
JCRE recovery semantics на всех fault-путях.

`deselect()` откатывает активную транзакцию, очищает transient key data и меняет
версии ключей. Это отдельная модельная операция; `selecting=True` само по себе
не исполняет маршрутизацию SELECT или applet deselect callback.

## DES и политика символических значений

`KeyBuilder` разрешает key type 2 и 64/128/192 bits, keyEncryption=false.
Cipher algorithm 1 — CBC NOPAD, 5 — ECB NOPAD; externalAccess=false.
Числовой mode модели: **2 — encrypt, 1 — decrypt**. В самом апплете P1=0 выбирает
encrypt; это отдельный уровень значений, его нельзя путать с Cipher mode.

`setKey` копирует slice по длине ключа, допускает символические байты в памяти
и увеличивает version. `init` требует initialized key, фиксирует mode/key_version
и IV (8 байт для CBC). `doFinal` проверяет длину, диапазоны и версию, затем требует
единственные значения input/key/IV. Результат вычисляется DES primitives и
записывается целиком; default IV после завершения снова нулевой.

`integer` использует `eval_upto(..., 2)` для доказательства единственности.
Единственная solver model разрешена; несколько значений дают `symbolic_api_argument`.
Такая политика сохраняет честную границу анализа: symbolic control flow возможен,
но криптографическое отношение не заменяется случайной конкретизацией.

## Пример программного использования

```python
from angr_integration.name1_demo import KEY, load_name1
from angr_integration.javacard_session import JavaCardSession

session = JavaCardSession(load_name1())
session.install()
result = session.transmit(0x20, p1=2, data=KEY)
assert not result.errored and not result.active
assert len(result.completed) == 1
assert result.summary()['completed'][0]['sw'] == '9000'
```

Для символического P1 передайте 8-битный BVS в `prepare_command`, затем `run`.
Не используйте один witness как доказательство покрытия. `name1_demo` проверяет
и попадание каждой ветви в ожидаемое условие, и отсутствие потерянных значений
в соответствующем множестве входов.

## Как добавлять модель

Нужны проверенный CAP key/signature, explicit declarations и контракт receiver.
Определите effects/state copy, transaction/transient behaviour, ошибки и допустимую
символичность каждого аргумента. Проверяйте ranges до mutation. Новый handler
должен возвращать declared type либо явное завершение/ошибку; нельзя возвращать
нулевую заглушку для неизвестной семантики.

Регрессии должны включать успешную команду, неверные параметры, fork isolation,
повторный вызов после ISOException, сохранение состояния между APDU и ожидаемую
ошибку на исходном CAP. Полный текущий сценарий — `name1_demo`, suite —
`angr_integration.tests.test_javacard`. Сверка с реальной картой остаётся отдельной
работой с AID/версией firmware и конкретным APDU transcript.
