# Тесты, фикстуры и воспроизводимость

[К документации](../README.md) · [Общее руководство](../PROJECT.md)

## Назначение

Тестовый слой фиксирует контракты преобразований и исполнения. Используется
стандартный `unittest`; дополнительные mocking-frameworks и CI workflow для
запуска всего набора документация не предполагает. Часть тестов строит synthetic
Soot IR, а часть проходит настоящий CAP от parser до angr. Эти уровни дополняют
друг друга и не являются взаимозаменяемыми доказательствами.

## Набор из 93 тестов

| Модуль | Количество | Что проверяет |
| --- | --- | --- |
| `pysoot_adapter/tests/test_adapter.py` | 19 | Реальные pysoot dataclasses, declaration/body consistency, statements/CFG, metadata и CAP integration |
| `angr_integration/tests/test_loader.py` | 18 | Loader/address map, call-state arguments, numeric execution, readiness и отказ от неизвестной семантики |
| `angr_integration/tests/test_heap.py` | 16 | Instance receiver/fields, arrays, casts/references, bounds и state copy isolation |
| `integration_tests/test_name1.py` | 14 | CAP 2.2, сравнение с JCA, original null field, interface signatures, binary boundaries и CAP 2.1 regression |
| `angr_integration/tests/test_calls.py` | 6 | Virtual по CAP token, special target/constructor, null receiver, signed remainder и possible-zero guard |
| `angr_integration/tests/test_javacard.py` | 20 | Install/APDU sequence, DES, symbolic P1, transactions/transient state, API identity и ограничения |

Число тестов соответствует текущему snapshot, а не автоматически обновляемому
счётчику документации. При добавлении/удалении теста обновите эту таблицу и общий
документ. Исторический успешный журнал — `JAVACARD_TEST_RESULTS.txt`; он относится
к проверенному окружению Linux. Windows execution отдельно не подтверждено.

Полный запуск из корня проекта:

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest pysoot_adapter.tests.test_adapter angr_integration.tests.test_loader angr_integration.tests.test_heap integration_tests.test_name1 angr_integration.tests.test_calls angr_integration.tests.test_javacard -v
```

Одна подсистема запускается тем же способом с одним module name. Все новые
регрессии должны завершаться за ограниченное число шагов и проверять отсутствие
неожиданных `errored` и оставшихся `active`, если заявляется завершение.

## Служебные определения тестовых модулей

Helpers `local`, `const/constant`, `unit`, `method/body`, `field`, `array`,
`adapt/load/declarations` создают небольшие тела и декларации непосредственно
на границах стадий. `signed`/`run_numeric` интерпретируют solver results с нужной
шириной. Они не являются публичным API приложения. `component` в integration
suite собирает минимальный бинарный CAP component для boundary checks.

`CallTests`, `RemainderTests`, `HeapTests`, `LoaderTests`, `JavaCardTests`,
`AdapterTests`, `CAPIntegrationTests`, `Name1Tests` и `BinaryBoundaryTests`
наследуют unittest.TestCase. Полный список функций и методов по каждому файлу
доступен в [SOURCE_MAP.md](../SOURCE_MAP.md).

## Фикстура examples/name1

| Файл | Роль |
| --- | --- |
| `name1.cap` | Неизменённый исполняемый CAP, основной вход анализа |
| `name1.jca` | Вывод converter для проверки mnemonic, offsets, tokens и signatures |
| `name1.java` | Читаемый исходник для понимания намерения апплета; не исполняется вместо CAP |
| `name1.exp` | Export собственных символов пакета; не заменяет exports библиотек Java Card |
| `symbols.json` | Явные names, imports и подпись interface DESKey.setKey |
| `input_manifest.json` | Хеши исходных материалов, в том числе reference native sources |
| `README.md` | Краткий вход в пример и команды; подробности в текущем комплекте docs |

Package AID — `112233445566`, версия 1.0; applet AID — `11223344556600`.
CAP SHA-256:
`edd4d74faea6ff1e37309bb0e6bf2bb35e94d97061c1f99c80f9766765941b65`.
Источником идентичности служит CAP/JCA, а не устаревший комментарий Java.

В CAP семь методов: `<init>` o1, `install` o56, `process` o76, `setDesKey` o142,
`setDesICV` o228, `getDesKey` o256, `doDesCipher` o306. Полный ключ содержит
префикс `112233445566@1.0:internal:t6:`. В классе есть `tempDesKey2`, но constructor
создаёт только `tempDesKey3`. Исходник намеренно не исправляется в baseline:
его null fault — ценный отрицательный regression test.

## Три демонстрационных entry point

| Команда | Источник тела | Результат |
| --- | --- | --- |
| `python -m angr_integration.demo` | Synthetic Soot IR | Два пути для sign(short), возвраты -7 и 7; `outputs/angr_demo` |
| `python -m angr_integration.memory_demo` | Synthetic instance method | Поле/массив и независимость fork; `outputs/angr_memory_demo` |
| `python -m angr_integration.name1_demo` | Настоящий CAP через весь pipeline | Install, APDU и API; `outputs/name1_execution` |

Каждая команда принимает `--output-root`. `name1_demo` также принимает `--cap`
и `--symbols`, но его assertions, AID-сообщение и APDU-протокол специализированы
для name1. Это не универсальный runner любого апплета только благодаря опции CAP.

## 15 APDU-сценариев name1_demo

| № | Сценарий | Ожидается |
| --- | --- | --- |
| 1 | `selecting=True` | `9000`, ранний return |
| 2 | Неизвестная INS | `6D00` |
| 3 | Cipher до ключа | `6985` |
| 4 | Установка ключа с P1=3 | `6A86` |
| 5 | P1=2, но только 16 байт ключа | `6700` |
| 6 | IV длиной 7 | `6700` |
| 7 | Первый receive 8 из 24 байт | `6700` |
| 8 | Cipher input длиной 7 | `6700` |
| 9 | Установка 24-байтового ключа | `9000` |
| 10 | Установка 8-байтового IV | `9000` |
| 11 | ECB encrypt | Совпадает известный ответ |
| 12 | ECB decrypt | Восстановлены исходные данные |
| 13 | CBC encrypt | Получен результат в модели |
| 14 | CBC decrypt | Восстановлены исходные данные |
| 15 | Установка 16-байтового ключа | `9000`; следующая попытка cipher проверяется отдельно как fault |

Дополнительно выполняются три символических пути P1 и одна ожидаемая ошибка
`null_reference` в getDesKey на bytecode offset 41. Они не входят в счётчик 15
обычных APDU-сценариев. Установка апплета также проверяется отдельно.

ECB known-answer vector приведён в коде из NIST SP 800-67 Appendix B.1, также
содержащегося в self-tests зависимости. Для CBC suite дополнительно сравнивает
модель с DES3 backend; одного round-trip недостаточно для доказательства верного
алгоритма, поскольку одинаковая ошибка encrypt/decrypt может компенсироваться.

## Проверка символических путей

P1 — свободный 8-битный BVS, data — конкретный ключ 24 байта. Ожидаемые множества:
`P1==2 → 9000`, `P1==1 → 6700`, `P1!=1 and P1!=2 → 6A86`.
Для каждого завершения проверяется невозможность выйти за своё условие и
невозможность потерять значения внутри него. Witness используется только
в отчёте как пример. Fork должен сохранять независимые persistent writes.

Отдельные проверки запрещают свободные symbolic crypto inputs, но разрешают
их после ограничения до единственного значения. Possible-zero remainder и
possible bounds fault не должны молча удалять неисправные входы из solver.

## Границы покрытия

93 теста подтверждают конкретные контракты и сценарии. Они не покрывают все
CAP components, malformed inputs, все комбинации bytecode и общий JCRE.
Legacy CFG verifier имеет непокрытые ошибочные ветви; есть несовместимость
handler data types и незавершённые parser paths. Эти факты зафиксированы в
[KNOWN_LIMITS.md](../KNOWN_LIMITS.md).

При найденной ошибке добавляйте минимальный тест, отличающий прежнее поведение
от исправленного. Для binary parser нужен маленький payload, для lowering —
небольшой метод, для runtime — наблюдаемые heap/return/errors/constraints. Fixture
реального апплета сохраняйте вместе с hashes и протоколом ожидаемых APDU; не
подгоняйте original CAP под удобный успешный результат.
