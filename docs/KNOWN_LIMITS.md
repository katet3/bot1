# Ограничения и технический долг текущего снимка

[К документации](README.md) · [Архитектурные решения](DECISIONS.md)

Документ отделяет намеренные границы модели от незавершённых или ошибочных ветвей
реализации. Перечень получен при чтении исходников и воспроизведении дефектов.
Статус обновлён 30 октября 2026 года: D-01–D-07 исправлены. Проходят
32 теста CAP linker/conversion, 35 тестов верификатора и 36 тестов CFG/IR — всего 103.
Остальные проблемы сохраняются.

## Подтверждённые проблемы ранних стадий

| ID | Место и наблюдение | Последствие | Статус и следующая проверяемая работа |
| --- | --- | --- | --- |
| D-01 | Пять вызовов в четырёх CFG rules передавали `VerificationError(code=...)`, dataclass ждёт `error_type` | Диагностика правила завершалась TypeError | **Исправлено:** все вызовы используют `error_type`; 15 тестов в `verification_engine/tests/test_cfg_rules.py` проверяют правила и их диагностику |
| D-02 | `RuleEngine.run` передавал список в `report.add_error` | В `report.errors` появлялся list вместо VerificationError, счётчик отражал число списков | **Исправлено:** используется `report.extend(errors)`; 10 тестов в `verification_engine/tests/test_rule_engine.py` проверяют плоский список, порядок, счётчик, текст, независимость запусков и merge |
| D-03 | RuleEngine индексировал концы рёбер до проверки их существования | KeyError раньше EdgeTargetRule | **Исправлено:** adjacency/reverse adjacency включают только рёбра с двумя существующими концами; исходные рёбра сохраняются для диагностики. 10 регрессий в `verification_engine/tests/test_invalid_edges.py` |
| D-04 | `build_exception_edges` ожидал dict, pipeline передаёт `jcvm_ir.Handler` | Непустая таблица вызывала TypeError; границы regions не выделялись, неизвестная цель пропускалась | **Исправлено:** общий валидатор method-local координат, leaders на start/end/target, явный отказ при неверных границах. 17 тестов в `cfg_generator/tests`, включая CAP metadata adapter → Soot traps |
| D-05 | CFG classifier не включал conditional `_w` и `athrow` | Потеря ветвлений, неверные блоки и обычное продолжение после throw | **Исправлено:** все 32 decoded conditionals, отдельный throw terminator без normal successor, leaders после всех terminators, явный отказ для `jsr/ret`. 19 тестов в `cfg_generator/tests/test_control_flow.py` |
| D-06 | Linker вычитал `...` для extended header; два поля читал как `u2` вместо `u1` | TypeError, поглощение начала тела и неверные offsets следующих методов | **Исправлено:** offset сохраняется до чтения; обычный/extended header занимает 2/4 байта. Проверяются доступность header/body и bytecode_count; результат публикуется после полного успеха. 16 регрессий. Typed adapter по-прежнему явно отклоняет extended methods |
| D-07 | `CAPFile.to_model()` заменял token/header/handlers на `None`, не передавал signature/static flag | Результат не подходил для typed IR; собранная таблица handlers терялась | **Исправлено:** фасад общего `methods_from_cap`, возвращающий `list[MethodInput]`; 16 регрессий metadata, координат, отказов и пути до Soot. Изменение типа результата и offset описано в руководстве CAP parser |
| D-08 | `BinaryReader.read_bytes` не требует полного диапазона; часть parsers использует raw fallback | Неполное единообразие boundary diagnostics и семантики operands | Strict reads, structured parse errors, malformed-input regressions |
| D-09 | Container не требует Applet, builder читает его безусловно | Library CAP без Applet завершается ошибкой | Определить contract library/app CAP, сделать requirement согласованным |
| D-10 | Components индексируются по короткому имени после чтения всего ZIP | Multi-package collisions, отсутствует общий лимит объёма контейнера | Reject duplicates/выбор пакета, ограничения ресурсов по задаче |
| D-11 | Standalone `jvm_like_ir` CLI не принимает interface signatures | Не подходит для name1 с invokeinterface | Добавить symbols option либо явно сохранить ограниченный CLI |
| D-12 | `requirements.txt` содержит `graphviz-0.21` | Это не intended version pin `graphviz==0.21` | Исправить manifest отдельным изменением; текущий no-png путь не зависит от него |

### Минимальные воспроизведения

До исправления D-01 `EmptyBlockRule.check` на блоке `instructions=[]` давал
`TypeError: VerificationError.__init__() got an unexpected keyword argument 'code'`.
Теперь правило возвращает `VerificationError(error_type='EMPTY_BLOCK', ...)`.
Новые тесты до исправления воспроизводили девять ошибок конструктора; после
исправления все 15 тестов проходят. Этот набор проверяет правила напрямую;
общий запуск на повреждённых рёбрах дополнительно покрыт тестами D-03.

До исправления D-02 правило, возвращающее `[VerificationError('example','example')]`,
оставляло в отчёте RuleEngine `type(report.errors[0]) == list`. Теперь список
разворачивается: элемент отчёта имеет тип `VerificationError`. До исправления
6 из 10 новых тестов агрегации падали; после него все 25 тестов D-01/D-02 проходят.

До исправления D-03 ребро `0 → 9` при единственном блоке 0 вызывало `KeyError`
при построении reverse adjacency. Теперь контекст строится, а EdgeTargetRule
возвращает `INVALID_EDGE_TARGET`. Ребро остаётся в исходном списке, но не попадает
ни в один индекс соседства. Отсутствие обоих концов даёт две диагностики.
До изменения 8 из 10 новых тестов падали с KeyError; после него проходят все
35 тестов D-01–D-03. Проверки построения CFG из байткода и контракт handlers
относятся к отдельным стадиям и не исправляются этой проверкой готового графа.

До исправления D-04 непустая таблица `jcvm_ir.Handler` приводила к
`TypeError: 'Handler' object is not subscriptable`. Теперь CFG принимает
method-local `start/end/target`, выделяет границы `[start, end)` и цель в блоки,
а неверные координаты отвергает с `ValueError`. Проверяются также прямые вызовы
построителя рёбер: отсутствие требуемого блока не скрывается. При ошибке позднего
обработчика построитель не оставляет частично изменённые adjacency и flags.
Все 17 новых тестов проходят; до исправления набор завершался с 38 ошибками,
включая subtests. Синтетические проверки проходят до Soot IR, но не проверяют
runtime dispatch исключений или разбор нового бинарного CAP с try/catch.

До исправления D-05 `ifeq_w` не разрывал блок и не создавал условные рёбра.
Последовательность `aconst_null; athrow; return` могла оказаться одним блоком,
а при наличии отдельного следующего блока `athrow` получал ложный fallthrough.
Теперь после throw начинается новый блок без обычного входящего ребра от throw;
при наличии защищающего handler добавляется только исключительное ребро.
`jsr/ret` явно отклоняются до построения блоков, даже в недостижимом коде.
Набор D-05 покрывает все 32 условные формы, оба направления и большие смещения,
остальные виды terminators, общие цели и согласованность с JCVM/Soot IR.
Все 19 новых и 52 прежних теста проходят. Это не реализация runtime throw/catch.

До исправления D-06 заголовок `80 10 00 20` читался как шестибайтовый:
`max_stack` и `max_locals` ошибочно использовали `u2`. При достаточном числе байтов
вычисление offset затем вычитало `Ellipsis` и давало `TypeError`; на коротком входе
ошибка чтения возникала раньше. Теперь три числовых поля extended header читаются
как `u1`, а blob-relative offset фиксируется до разбора. Последовательность обычного,
расширенного и обычного метода с телами длиной 2, 3 и 1 байт даёт offsets 0, 4, 11.
Усечённые заголовок/тело дают `ValueError` с координатой; при ошибке позднего метода
предыдущий полный список `methods` сохраняется. Все 16 новых и 71 прежний тест
проходят. Это структурное чтение, не поддержка extended methods в typed pipeline.

До исправления D-07 обычный метод с сохранёнными header limits терял их в
`to_model()`: поля становились `None`, и IRBuilder сообщал `Missing/invalid max_stack`.
Даже непустая таблица handlers превращалась в `None`. Теперь публичный метод
возвращает canonical `MethodInput` через общий adapter; signatures и координаты
соответствуют основному конвейеру. Все 16 новых и 87 прежних тестов проходят.
Legacy `Method`/`ExceptionHandler` не удалены, но больше не являются результатом
этого API. Extended methods по-прежнему явно отклоняются typed adapter.

В рамках D-08 отдельно подтверждено расхождение `ilookupswitch`: decoder читает
npairs как один байт, а `jcvm_ir.lowering` считает двухбайтовое поле в длине
инструкции. На входе с одной парой decoder ставит следующую инструкцию на offset 11,
IR ожидает 12 (`Noncontiguous instruction at 11; expected 12`). D-05 проверяет
CFG для четырёх switch-форм по декодированным Instruction, не исправляет их
бинарный формат и не объявляет этот путь сквозным.

Эти наблюдения ограничивают доверие к invalid-input diagnostics. Они не отменяют
исторический результат 93 тестов на покрытых сценариях, но показывают, почему одного их числа
недостаточно для заявления о полном verifier или безопасном разборе любого CAP.

## Намеренные границы преобразования

Поддерживается выбранный concrete-method subset. CAP linker читает структурные
заголовки размером 2/4 байта; typed adapter принимает только ordinary concrete
headers и отклоняет остальные до декодирования тела. Наличие enum CAP version 2.3
либо opcode в таблице не означает сквозную поддержку. Abstract/native methods,
lowering extended methods и общая валидация linker требуют самостоятельной разработки.
`instanceof` и ряд decoded operands не имеют полного lowering. Для `jsr/ret`
нет модели return-address; после D-05 они отвергаются уже в CFG с `ValueError`.

Reference inference консервативен: смешанные типы могут стать Object и заблокировать
операцию, которой нужен точный array type. Полного hierarchy-aware LUB и общей
SSA/phi формы для local slots нет. Soot text экспортируется для диагностики;
нет Java compiler round-trip и обратного importer диагностического pysoot JSON.

## Намеренные границы исполнения

| Область | Текущая граница |
| --- | --- |
| Арифметика | Runtime whitelist не включает general div, shifts и unary; rem поддержан с possible-zero guard |
| Исключения | Traps/throw сохраняются в IR, но general dispatch/unwind не реализован |
| Классы | Static fields, `<clinit>`, общий class initialization отсутствуют |
| Интерфейсы | Нет общей CAP interface→virtual token map; DESKey работает только через explicit model |
| Heap | Нет symbolic object choice; размеры и reference-array index однозначны; merge/widen отвергаются |
| Возможные faults | Состояние останавливается; автоматического normal/exception split нет |
| Allocation | Analysis limit массива; object/constructor verification не равен полному JVM verifier |
| API | Только name1 subset и точные tokens/signatures, без fallback заглушек |
| APDU | Один applet/channel, input до 255, buffer 260, один receive, без Le/extended/transport |
| Crypto | Concrete/uniquely constrained DES data/key/IV; нет свободных symbolic crypto formulas |
| Transactions | Snapshot значений; нет NVM/commit-buffer/power-loss модели; allocation внутри transaction запрещён |
| JCRE | Selecting flag задаёт harness; нет полного SELECT routing/firewall/GP |

## Границы отчётности и сессии

`CommandRun.summary()` требует однозначных SW/response для concrete сериализации;
само наличие symbolic BV в завершённом состоянии не означает, что summary умеет
его представить. API summary для symbolic responses — отдельная будущая задача.

`JavaCardSession.choose` проверяет project и завершённость, но не хранит закрытый
реестр только собственных результатов. При нескольких sessions одного project
клиент обязан выбрать соответствующее своей последовательности состояние.

Cleanup открытой транзакции реализован для deadended states, включая ISOExit.
Произвольные engine errors остаются остановками; нельзя считать, что весь JCRE
автоматически восстановлен после любой ошибки. Продолжение после fault требует
явной модели, а не повторного использования errored.state как успешного.

Экспорты не атомарны и не очищают старые method_N files. Число/состав методов
сверяются по program/report, не по одному каталогу. Historical test logs и UPDATE
files описывают свою версию; источник текущего статуса — code snapshot + docs.

## Приоритеты сопровождения

После D-01–D-07 следующий пункт списка — D-08: проверки binary boundaries,
strict reads и согласование ширины npairs в `ilookupswitch`.
Также нужна полноценная CAP-фикстура с непустой таблицей обработчиков.
Синтетический бинарный Method component уже проверяется до Soot в D-06,
но не заменяет такой архив. Новый execution feature можно добавлять
с уверенностью, что ранние стадии не искажают его вход.

General exception dispatch, interface maps, static initialization и расширение
JCRE — самостоятельные архитектурные задачи. Для каждой требуется явный контракт
состояния и набор наблюдаемых исходов. Сравнение с реальной картой должно фиксировать
firmware/API versions и APDU transcript; успешное совпадение одной команды не
доказывает полную эквивалентность модели.
