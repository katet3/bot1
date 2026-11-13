# cap_decompile — бинарный формат CAP и структурная модель

[К документации](../README.md) · [Каталог исходников](../SOURCE_MAP.md)

## Роль в архитектуре

Подсистема преобразует ZIP/CAP в типизированные компоненты и декодированные
инструкции. Она сохраняет CP tokens, flags, размеры и offsets, но не разрешает
все Java-имена и не исполняет байткод. Внешние имена и API-контракты добавляются
позже через `SymbolTable` и профиль runtime.

Рабочий вход конвейера: `CAPContainer.load()` → `CAPFileBuilder.build(container)`.
Методы для следующей стадии извлекаются через `jcvm_ir.methods_from_cap(cap)`
либо `cap.to_model()`. После D-07 второй вызов делегирует первому и возвращает
тот же `list[MethodInput]`. Проверки Descriptor, заголовка и координат обработчиков
сосредоточены в одном adapter; второго варианта преобразования больше нет.

## Контракты данных

| Объект | Что хранит | Что важно сохранять |
| --- | --- | --- |
| `CAPContainer.components` | short component name → bytes | Исходный payload единственного проверенного каталога; новый словарь публикуется только после полного успешного чтения |
| `CAPContainer.component_directory` | Полный путь каталога внутри ZIP | `None` до первой успешной загрузки; например, `pkg/javacard` или `javacard` |
| `ZipLimits` | Ограничения физического ZIP и размеров записей | Неизменяемая политика анализатора; все значения — положительные `int` |
| `CAPFile` | Header, Directory, Import, необязательный Applet, CP, Class, Method, StaticField, RefLocation, Descriptor | `applet=None` для library CAP; историческое поле `import_componet` написано именно так |
| `MethodInfo` | Header, bytecodes, handler slice, offset | Начало header относительно methods blob, без handler_count и таблицы handlers; не равно публичному CAP key |
| `Instruction` | `offset`, `opcode`, `mnemonic`, `operands` | Offset от начала bytecode тела; branch targets уже абсолютные внутри метода |
| `ExceptionHandlerInfo` | start, active length, handler offset, catch index, stop bit | Перевод координат выполняет adapter JCVM |

Компонент имеет tag и u2 size; размер относится к info-части. `BinaryReader`
читает big-endian u1/u2/u4 и хранит курсор. После D-08 перед каждым чтением
проверяется полный диапазон: укороченные bytes не возвращаются, курсор при ошибке
не изменяется. Это проверка физического буфера; ограничения declared size,
counts, flags и связей между компонентами остаются обязанностью их parsers/verifier.

## Строгое чтение и диагностика D-08

`require_range(data, offset, length, context=...)` проверяет диапазон
`[offset, offset + length)` до чтения, выделения таблицы или изменения курсора.
Offset и length должны быть целыми `int`; `bool`, float, отрицательные значения
и выход за буфер отвергаются. Нулевая длина допустима, в том числе на EOF.
`seek` допускает обе границы буфера и явную перемотку; `skip` принимает только
неотрицательную длину. Для перемещения назад следует использовать `seek`.

`BinaryParseError(ValueError)` содержит `context`, `offset`, `needed`, `available`.
Последние два поля заполнены для усечённого диапазона; у остальных ошибок могут
быть `None`. `offset` относится к переданному буферу: у компонентного reader это
обычно весь component с tag/size, у decoder — bytecode тело метода. При усечении
switch-таблицы это начало таблицы, а `context` содержит mnemonic. Это не CAP key.
Существующие обработчики `ValueError` продолжают работать. Часть проверок формата
в компонентах по-прежнему возвращает обычный `ValueError`; новая иерархия не
объявляется универсальной для всех ошибок проекта.

Атомарность относится к одной операции reader. Parser мог успешно прочитать count
перед ошибкой payload; автоматического отката всего parser нет. Аналогично
`parse_bytecode` не возвращает частичный список после ошибки.

Все формы операндов в таблице декодера разбираются явно. Неизвестный opcode или
неописанный формат дают `BinaryParseError`; сырые байты не выдаются за готовые
числовые operands. Для `iipush` сохраняется signed int, для static field indices —
один unsigned u2, для increments — unsigned index и signed constant.

| Инструкция | Уточнённый бинарный контракт |
| --- | --- |
| `slookupswitch`, `ilookupswitch` | `npairs:u2`; полный payload проверяется до цикла, keys строго возрастают |
| `stableswitch`, `itableswitch` | Полный header и `high-low+1` offsets проверяются до цикла; `high < low` запрещено |
| `sinc_w`, `iinc_w` | `index:u1`, `constant:s2`; длина инструкции 4 байта |
| `dup_x`, `swap_x` | Один байт `mn`; длина инструкции 2 байта |

Форматы сверены с [Oracle JCVM 3.0.5, §7.5](https://docs.oracle.com/cd/E59935_01/JCVMS.pdf).
Нормализация branch targets остаётся относительной к opcode внутри метода.
Проверки допустимости целей и стека выполняются CFG/IR; декодирование само по себе
не включает lowering или runtime support. Для wide increments и `dup_x/swap_x`
lowering по-прежнему явно отсутствует. Сырые payload полей вроде Descriptor types
сохраняются намеренно для последующей стадии; это не удалённый operand fallback.

## Последовательность разбора

1. `ZipReader` проверяет физический размер и каталог ZIP без распаковки записей.
   `CAPContainer` требует один каталог с прямыми дочерними `.cap`-файлами внутри
   `javacard/` и полный обязательный набор. После этих проверок `ZipReader`
   читает только выбранные компоненты с ограничением размера.
2. Header определяет CAP version, package AID/version и optional package name.
3. Остальные `parse_from_bytes` получают эту версию и разбирают свой компонент.
4. `CAPFile.validate()` сверяет размер Header с Directory и контракт наличия Applet:
   ACC_APPLET, component_sizes[2] и applet_count.
5. `CAPFile.link()` вызывает `MethodComponent.link_with_descriptor`.
6. Linker последовательно читает headers и тела по bytecode_count из Descriptor.
   До header сохраняется курсор; перед чтением проверяются доступность header/body
   и неотрицательный целочисленный bytecode_count. Новый список methods публикуется
   только после чтения всех методов. `methods_from_cap` затем сопоставляет
   offset/сигнатуры и проверяет согласованность.

## Однозначный ZIP и ограниченное чтение: контракт D-10

Сначала строится индекс `полный путь → ZipInfo`. Повторное полное имя — ошибка,
даже если payload одинаков. Все имена должны быть относительными POSIX-путями:
запрещены начальный `/`, обратная косая черта, пустые сегменты, `.` и `..`,
NUL и двоеточие в первом сегменте. Не допускается изменение имени самим `ZipInfo`
при его чтении. Имена чувствительны к регистру; нормализация для устранения
неоднозначности не выполняется. Записи каталогов с завершающим `/` допустимы.
Файлы из архива на файловую систему не извлекаются.

Компоненты — прямые дочерние файлы с суффиксом `.cap` в `javacard/` или
`<prefix>/javacard/`. Вложенный `pkg/javacard/nested/Header.cap` отклоняется.
Файл `notes/Header.cap` вне `javacard/` считается вспомогательным. Если компоненты
найдены в двух каталогах, загрузка отклоняется с перечислением каталогов:
пакет не выбирается автоматически, неполные наборы не объединяются.
Проверка обязательных компонентов также выполняется до открытия payload.

Только после проверки единственного каталога компоненты получают короткие ключи
в `CAPContainer.components`. Поэтому `get_component('Header.cap')` остаётся
совместимым с builder без потери происхождения и без перезаписи другого пакета.
Контракт допускает один пакет, а не обязательно один апплет: содержимое Applet
разбирается следующей стадией.

`ZipReader.read_selected(selector)` передаёт selector неизменяемый tuple полных
имён. Возвращённые имена проверяются целиком до чтения: отсутствующее имя даёт
`KeyError`, повтор в выборе — `ValueError`. Индекс и payload читаются из одного
открытого архива. `list_files()` читает только каталог; `read_file()` и совместимый
`read_all()` используют ту же политику проверки. Container больше не вызывает
`read_all()`; вспомогательные payload не распаковываются и их CRC не проверяется.

### Политика размера

| Поле `ZipLimits` | По умолчанию | Что ограничивает |
| --- | --- | --- |
| `max_archive_bytes` | 16 MiB | Физический размер открытого ZIP до создания `ZipFile` |
| `max_members` | 1024 | Число всех записей, включая записи каталогов |
| `max_member_bytes` | 2 MiB | Заявленный распакованный размер каждой записи |
| `max_total_bytes` | 16 MiB | Сумму заявленных распакованных размеров всех записей |

MiB означает `1024 * 1024` байт. Ограничения применяются ко всему архиву, в том
числе к невыбранным записям. Допустимы только `ZIP_STORED` и `ZIP_DEFLATED`;
зашифрованные записи и другие методы сжатия отклоняются при проверке каталога.
Это ограничения среды анализа, а не требования спецификации Java Card.

Для задачи с более крупным допустимым входом политика задаётся через Python API:

```python
from pathlib import Path
from cap_decompile.container.cap_container import CAPContainer
from cap_decompile.container.zip_reader import ZipLimits

container = CAPContainer(Path('application.cap'), limits=ZipLimits(
    max_archive_bytes=32 * 1024 * 1024,
    max_total_bytes=32 * 1024 * 1024,
))
container.load()
```

Неуказанные поля сохраняют значения по умолчанию. Ноль не отключает проверку:
каждое поле требует положительный `int`, включая запрет `bool`. Новых CLI-флагов
для этих параметров нет; обычный `main.py` использует политику по умолчанию.

Payload читается по `ZipInfo` порциями не более 64 KiB. Reader проверяет длину
полученного потока против заявленной и допустимой, не возвращает частичные bytes.
CRC и повреждения читаемых записей проверяет `zipfile`; ошибки формата ZIP,
CRC и распаковки преобразуются в `ValueError`. Существующий CLI выводит ошибку
конвейера и завершается с кодом 1.

Физический размер проверяется на том же открытом файле через `fstat`. Стандартный
`ZipFile` затем разбирает central directory в памяти; лимит числа записей проверяется
после этого разбора. Поэтому лимиты не являются жёсткой квотой RAM/CPU или времени
процесса. Все выбранные payload остаются bytes в памяти, но ограничены политикой
входных данных. Это не потоковый parser компонентов и не полная CAP-верификация.

### Повторная загрузка

`CAPContainer.load()` сначала получает новый полный результат в локальных данных.
При успехе он целиком заменяет `components` и `component_directory`: необязательный
компонент из предыдущего архива не остаётся в новом. При отказе, в том числе
на последнем читаемом компоненте, сохраняется предыдущий успешный снимок.
Вызывающий код обязан обработать исключение; старый снимок не означает успешную
загрузку нового файла.

## Необязательный Applet component: контракт D-09

`Applet.cap` не входит в обязательный набор: библиотечный пакет может содержать
классы и методы без устанавливаемых апплетов. `get_component(name)` сохраняет
строгий доступ и KeyError при отсутствии записи. Новый
`get_optional_component(name)` возвращает `None` только при отсутствии; пустые
bytes означают присутствующий повреждённый компонент и передаются parser-у.

Builder хранит `CAPFile.applet: AppletComponent | None`, не создавая фиктивного
компонента с нулевым count. Межкомпонентные проверки выполняются после разбора:

| Applet.cap | Header ACC_APPLET (0x04) | Directory | Результат |
| --- | --- | --- | --- |
| Отсутствует | Снят | size=0, applet_count=0 | Library CAP, `applet=None` |
| Присутствует и корректен | Установлен | Размер и count совпадают с Applet | Applet CAP |
| Отсутствует, но объявлен Header или Directory | Любой | Есть противоречие | ValueError с указанием отсутствующего Applet.cap |
| Присутствует без флага или с несовпадающими size/count | Любой | Есть противоречие | ValueError |

Проверки соответствуют Java Card VM Specification, разделам 6.4–6.6.
Остальные обязательные компоненты остаются обязательными. Общая проверка всех
flags и межкомпонентных связей этим изменением не заявляется.

`metadata_from_cap` передаёт library CAP с `ProgramMetadata.applets=()`.
Внешние пользователи `cap.applet.applets` должны сначала проверить `cap.applet is not None`.
Методы библиотеки проходят обычный typed pipeline. Для исполнения задаётся
поддержанный метод и его аргументы; установка через `JavaCardSession` требует
ровно один настоящий апплет. Несколько методов не дают автоматическую entry point.

## Публичное преобразование и миграция D-07

Раньше `to_model()` декодировал инструкции, но заполнял поля заголовка и token
значением `None`; собранный список handlers отбрасывался. Signature и static flag
отсутствовали. Даже заполнение только числовых полей не сделало бы этот результат
пригодным для typed IR: требуются корректные координаты и тип `jcvm_ir.Handler`.

Теперь `CAPFile.to_model()` — фасад `methods_from_cap(self)`. Используется общий
join по info-relative offset, а не по порядку linked methods или token. Token
может повторяться в разных классах. Сохраняются signature, `is_static`, header
limits, bytecodes, instructions, имя метода и упорядоченная таблица handlers.

| Контракт | До D-07 | После D-07 |
| --- | --- | --- |
| Тип результата | `list[cap_decompile.model.method_info.Method]` | `list[jcvm_ir.MethodInput]` |
| `token`, `max_stack`, `nargs`, `max_locals` | `None` | Значения Descriptor/header, проверенные общим adapter |
| `name`, `signature`, `is_static` | Отсутствуют | Имя с AID/class offset/method offset, разобранная подпись, static flag |
| `offset` | Начало header относительно methods blob | Начало header относительно info-части Method component |
| `exception_handlers` | `None` | `tuple[jcvm_ir.Handler, ...]` в координатах bytecode тела, включая пустой tuple |
| `is_extended` | `None` | Поля нет; unsupported headers явно отвергаются |

Клиенты, проверяющие тип `Method`, должны перейти на `MethodInput`. Сырой header
доступен в `cap.method_component.methods[*].header`; это отдельный структурный API.
Для прежней blob-relative координаты из `MethodInput.offset` вычитается
`1 + 8 * cap.method_component.handler_count`. Повторно сдвигать handlers нельзя:
`start/end/target` уже method-local, диапазон `[start, end)`.

Существующие вызовы `cap.to_model()` без аргументов сохраняются. Методы возвращаются
в порядке Descriptor; повторный вызов создаёт новый список и новые decoded instructions.
CAP не изменяется и не линкуется повторно. Неполные/несогласованные linked metadata
приводят к `IRValidationError` общего adapter. Пустая согласованная модель даёт `[]`;
корневой `main.extract_methods` отдельно запрещает пустой набор для своего CLI.

Импорт adapter выполняется внутри `to_model()`. Обычный импорт и структурное чтение
`cap_decompile` не загружают JCVM IR или runtime. При вызове требуется установленный
код `jcvm_ir` из этого же проекта; angr/pysoot для преобразования не требуются.
Legacy dataclasses `Method`/`ExceptionHandler` оставлены доступными для старых
импортов, но не являются результатом этого API и не заменяют typed input.

## Версии и исправления для name1

Для CAP 2.2+ Header содержит package_name_info, Directory — 12 записей размеров
вместо 11 для 2.1, Class — начальный signature pool. Эти различия влияют на offsets.
Class parser сохраняет info-relative offset каждой декларации; adapter соединяет
Class и Descriptor по нему, а не по порядку в списках.

`checkcast` и `instanceof` занимают 4 байта: opcode, atype, u2 index.
`invokeinterface` занимает 5 байт: opcode, nargs, u2 class index, method token.
Декодер сохраняет эти operands отдельно. Семантика `instanceof` пока не добавлена
в JCVM IR. Распознавание opcode не означает сквозную поддержку операции.

## Модули контейнера и модели

| Python-модуль | Основные определения | Назначение и контракт сопровождения |
| --- | --- | --- |
| `container/zip_reader.py` | `ZipLimits`, `ZipReader` | Проверка полного индекса и лимитов; `list_files`, `read_selected`, `read_file`, `read_all`; без интерпретации компонентов |
| `container/cap_container.py` | `CAPContainer` | Единственный каталог компонентов, required-set, атомарная публикация результата и доступ по короткому имени; debug hex-print не участвует в семантике |
| `model/cap_file.py` | `CAPFile`, `CAPFileBuilder` | Композиция parsers, validate/link; `to_model` делегирует typed adapter, lowering здесь не выполняется |
| `model/method_info.py` | `Instruction`, `Method`, `ExceptionHandler`, `parse_bytecode`, switch parsers | Таблица opcode/длины, signed/unsigned operands, method-local targets; `Method`/`ExceptionHandler` — legacy containers |
| `model/constant_pool_entries.py` | Нет | Пустая заготовка; рабочие CP-модели находятся в `components/constant_pool.py` |
| `model/references.py` | Нет | Пустая заготовка; семантический `Reference` находится в `jcvm_ir/model.py` |
| `parser.py` | Нет | Пустой файл; не является entry point |
| `validation/validator.py` | Нет | Общий бинарный валидатор не реализован |
| `validation/invariants.py` | Нет | Общий реестр CAP-инвариантов не реализован |
| `main.py` | `main` | Старый debug script с локальными импортами и фиксированным CAP; production CLI — корневой `main.py` |
| `__init__.py` | Нет | Пустой маркер пакета |

## Модули компонентов

| Python-модуль | Основные определения | Ответственность |
| --- | --- | --- |
| `components/base.py` | `CAPComponent` | Общие tag/size для dataclass-компонентов |
| `components/binary_reader.py` | `BinaryReader`, `BinaryParseError`, `require_range` | Полные диапазоны чтения, стабильный курсор при отказе, структурированная диагностика |
| `components/header.py` | `CAPVersion`, `PackageInfo`, `HeaderComponent` | Magic, CAP version, flags, package AID/version/name; проверяет tag/size и основные границы |
| `components/directory.py` | `StaticFieldSizeInfo`, `CustomComponentInfo`, `DirectoryComponent` | Version-aware таблица размеров, counts и custom component descriptors |
| `components/applet.py` | `AppletInfo`, `AppletComponent` | AID каждого applet и offset его install |
| `components/import_component.py` | `PackageInfo`, `ImportComponent` | Упорядоченный список импортов; index служит package token |
| `components/constant_pool.py` | `CPInfo`, `ConstantClassref`, `ConstantFieldOrMethodRef`, `ConstantStaticRef`, parse helpers | Различение внутренних/external class, field и method references |
| `components/class_component.py` | `ClassRef`, `TypeDescriptor`, `InterfaceInfo`, `ClassInfo`, remote/interface helpers, `ClassComponent` | Class/signature pool, наследование, интерфейсы и info-relative offsets |
| `components/method_component.py` | `MethodHeaderInfo`, `ExtendedMethodHeaderInfo`, `ExceptionHandlerInfo`, `MethodInfo`, `MethodComponent` | Handler table, methods blob, последовательная привязка к Descriptor |
| `components/static_field.py` | `ArrayInitInfo`, `StaticFieldComponent` | Начальный образ static storage и array initializers; runtime static fields этим не включаются |
| `components/reference_location.py` | `ReferenceLocationComponent` | Данные расположения ссылок; не является таблицей Java-имён |
| `components/descriptor.py` | `FieldRef`, field/method/class/type descriptor dataclasses, `DescriptorComponent` | Декларации, access flags, bytecode counts и raw type descriptors |

Полные определения каждого файла перечислены в [SOURCE_MAP](../SOURCE_MAP.md).
Типы Descriptor декодируются из nibble-потока в `jcvm_ir.DescriptorTypes`;
это намеренная граница между чтением структуры и её семантическим использованием.

## Ограничения и обнаруженные дефекты

После D-06 структурный parser различает два формата:

| Формат | Размер | Поля после первого байта |
| --- | --- | --- |
| Ordinary | 2 байта | `nargs` и `max_locals` в двух nibble второго байта; `max_stack` в первом |
| Extended (`flags & 0x8`) | 4 байта | `max_stack`, `nargs`, `max_locals` — по одному `u1` |

Первый байт содержит flags и, для extended, нулевой padding. Формат сверяется с
[Oracle Java Card VM Specification 3.0.5, §6.10.3](https://docs.oracle.com/cd/E59935_01/JCVMS.pdf).
Раньше `max_stack` и `max_locals` extended header читались как `u2`, а обратный
расчёт offset вычитал `...`. Теперь `MethodInfo.offset` равен курсору **перед**
header: длина заголовка не участвует в обратном расчёте. Handler table остаётся
в прежних info-relative координатах; её размер не прибавляется к blob offset.

Усечённые header/body, ненулевой extended padding и неверный bytecode_count дают
`ValueError` с blob offset. Счётчик должен быть `int >= 0`; `bool` не принимается.
При ошибке позднего метода linker не заменяет прежний полный список частичным.
Повторная успешная линковка заменяет список, не добавляет дубликаты.

Это дополнительные проверки linker поверх строгих операций BinaryReader D-08.
Последовательный порядок Descriptor сохраняется: поиск методов через seek по
descriptor offset, gaps, проверка всех handler slices и лишних байтов здесь
не добавлены. Flags структурно сохраняются; полноценный verifier заголовков
и abstract/native semantics не реализованы.

Поддержанный сквозной путь использует обычные concrete method headers.
`methods_from_cap` явно отвергает остальные **до** декодирования тела и расчёта
его начала как `descriptor.method_offset + 2`. Корректное чтение extended header
не включает его преобразование или исполнение; этот отказ покрыт тестом.

Таблица OPCODES шире семантического поднабора. Исправление формата operand не
реализует его stack/runtime semantics: unsupported операции по-прежнему отклоняет
typed IR. D-08 устраняет короткие чтения и raw fallback; полная проверка всех
структур CAP, версий и межкомпонентных ограничений остаётся отдельной задачей.

## Как изменять

Новый компонент должен возвращать структурную модель и проверять потребление
payload. Версионную ветку следует выбирать по Header, не по Java-комментариям
или имени файла. Для новой инструкции одновременно меняются длина, структура
operands и тест method-local offsets. После parser-теста выполняется JCVM lowering:
он обнаруживает рассинхронизацию покрытия байткода.

Регрессии D-06: [test_method_headers.py](../../cap_decompile/tests/test_method_headers.py),
16 тестов. Они проверяют оба формата и смешанные методы, handler prefix, усечение,
повторную линковку и сохранение результата при ошибке. Бинарный Method component
с ordinary header и handler проходит adapter → CFG → JCVM → JVM-like → Soot;
extended header доходит до ожидаемого отказа typed adapter без вызова decoder.
Регрессии D-07: [test_model_conversion.py](../../cap_decompile/tests/test_model_conversion.py),
ещё 16 тестов. Проверяются metadata для static/instance методов, нулевые значения,
ordered handlers, join по offset, отклонение несогласованных входов, два реальных
CAP и путь `to_model()` → Soot на бинарном Method component с handler.
Отдельная проверка подтверждает, что импорт parser не загружает IR/runtime.
Регрессии D-08: [test_binary_reader.py](../../cap_decompile/tests/test_binary_reader.py)
(12 тестов) и [test_bytecode_decoding.py](../../cap_decompile/tests/test_bytecode_decoding.py)
(20 тестов). Проверяются полные/усечённые чтения, каждый обрезанный префикс десяти
реальных компонентов, все fixed opcode layouts, переменные таблицы и четыре
бинарные switch-формы до Soot. Вместе наборы содержат 64 теста и не зависят
от angr, pysoot или Graphviz:

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest discover -s cap_decompile/tests -p "test_*.py" -v
```

Интеграционные проверки реального CAP находятся также в `CAPIntegrationTests`
из [test_adapter.py](../../pysoot_adapter/tests/test_adapter.py); они требуют
корректных interface signatures в вызываемом pipeline. Исторический
`integration_tests/test_name1.py` отсутствует в базовой Git-ревизии этого обновления.
Нужны отдельные будущие тесты malformed components, отсутствующего Applet
и collision компонентов нескольких пакетов.
