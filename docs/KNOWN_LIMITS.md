# Ограничения и технический долг текущего снимка

[К документации](README.md) · [Архитектурные решения](DECISIONS.md)

Документ отделяет намеренные границы модели от незавершённых или ошибочных ветвей
реализации. Перечень получен при чтении исходников; три небольших воспроизведения
ошибочной диагностики/handler contract выполнены отдельно. Документационный
комплект не исправляет перечисленные дефекты.

## Подтверждённые проблемы ранних стадий

| ID | Место и наблюдение | Последствие | Следующая проверяемая работа |
| --- | --- | --- | --- |
| D-01 | Несколько CFG rules передают `VerificationError(code=...)`, dataclass ждёт `error_type` | Пустой блок, неверный entry и другие нарушения могут вызвать TypeError вместо отчёта | Унифицировать argument name; негативные tests для каждого rule |
| D-02 | `RuleEngine.run` передаёт список в `report.add_error` | В `report.errors` появляется list вместо VerificationError, счётчик/формат неоднозначны | Использовать согласованный плоский контракт, тест aggregation/merge |
| D-03 | RuleEngine строит adjacency до проверки концов рёбер | KeyError на malformed edge раньше EdgeTargetRule | Безопасный context либо предварительная validation endpoints |
| D-04 | `build_exception_edges` ждёт dict, pipeline передаёт `jcvm_ir.Handler` | При непустом handler table — TypeError; name1 его не содержит | Единый typed handler contract, leaders на границах regions |
| D-05 | CFG classifier не включает все формы decoder, в частности conditional `_w`/athrow | Неверное раннее разбиение; позже возможен CFG mismatch | Общая нормализованная классификация и tests каждого terminator |
| D-06 | В extended-header offset linker используется `...` вместо длины | Возможен TypeError до явного отказа adapter | Явно отвергать unsupported header раньше либо реализовать формат полностью |
| D-07 | `CAPFile.to_model()` теряет metadata | Невозможно безопасно строить typed IR из его результата | Использовать `methods_from_cap`; позднее удалить/обновить legacy API |
| D-08 | `BinaryReader.read_bytes` не требует полного диапазона; часть parsers использует raw fallback | Неполное единообразие boundary diagnostics и семантики operands | Strict reads, structured parse errors, malformed-input regressions |
| D-09 | Container не требует Applet, builder читает его безусловно | Library CAP без Applet завершается ошибкой | Определить contract library/app CAP, сделать requirement согласованным |
| D-10 | Components индексируются по короткому имени после чтения всего ZIP | Multi-package collisions, отсутствует общий лимит объёма контейнера | Reject duplicates/выбор пакета, ограничения ресурсов по задаче |
| D-11 | Standalone `jvm_like_ir` CLI не принимает interface signatures | Не подходит для name1 с invokeinterface | Добавить symbols option либо явно сохранить ограниченный CLI |
| D-12 | `requirements.txt` содержит `graphviz-0.21` | Это не intended version pin `graphviz==0.21` | Исправить manifest отдельным изменением; текущий no-png путь не зависит от него |

### Минимальные воспроизведения

`EmptyBlockRule.check` на блоке `instructions=[]` даёт
`TypeError: VerificationError.__init__() got an unexpected keyword argument 'code'`.
Rule, возвращающее `[VerificationError('example','example')]`, после RuleEngine
оставляет `type(report.errors[0]) == list`. `build_exception_edges` с tuple из
`Handler(0,1,0,0)` даёт `TypeError: 'Handler' object is not subscriptable`.

Эти наблюдения ограничивают доверие к invalid-input diagnostics. Они не отменяют
результат 93 тестов на покрытых сценариях, но показывают, почему одного их числа
недостаточно для заявления о полном verifier или безопасном разборе любого CAP.

## Намеренные границы преобразования

Поддерживается выбранный concrete-method subset. Наличие enum CAP version 2.3,
parser dataclass extended header либо opcode в таблице не означает сквозную
поддержку. Abstract/native/linker edge cases требуют самостоятельной разработки.
`instanceof`, jsr/ret и ряд decoded operands не имеют полного lowering.

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

Сначала целесообразно закрыть D-01..D-04: они мешают получать надёжные отрицательные
диагностики и принимать следующий CAP с handlers. Затем согласовать CFG opcode
coverage и binary boundaries. После этого новый execution feature можно добавлять
с уверенностью, что ранние стадии не искажают его вход.

General exception dispatch, interface maps, static initialization и расширение
JCRE — самостоятельные архитектурные задачи. Для каждой требуется явный контракт
состояния и набор наблюдаемых исходов. Сравнение с реальной картой должно фиксировать
firmware/API versions и APDU transcript; успешное совпадение одной команды не
доказывает полную эквивалентность модели.
