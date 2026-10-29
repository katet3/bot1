# cap_decompile — бинарный формат CAP и структурная модель

[К документации](../README.md) · [Каталог исходников](../SOURCE_MAP.md)

## Роль в архитектуре

Подсистема преобразует ZIP/CAP в типизированные компоненты и декодированные
инструкции. Она сохраняет CP tokens, flags, размеры и offsets, но не разрешает
все Java-имена и не исполняет байткод. Внешние имена и API-контракты добавляются
позже через `SymbolTable` и профиль runtime.

Рабочий вход конвейера: `CAPContainer.load()` → `CAPFileBuilder.build(container)`.
Методы для следующей стадии извлекаются через `jcvm_ir.methods_from_cap(cap)`.
Старый `CAPFile.to_model()` не следует использовать для новых интеграций: он
не передаёт достаточные заголовки, подписи и exception metadata.

## Контракты данных

| Объект | Что хранит | Что важно сохранять |
| --- | --- | --- |
| `CAPContainer.components` | short component name → bytes | Исходный бинарный payload без преобразования |
| `CAPFile` | Header, Directory, Import, Applet, CP, Class, Method, StaticField, RefLocation, Descriptor | Связь между компонентами; историческое поле `import_componet` написано именно так |
| `MethodInfo` | Header, bytecodes, handler slice, offset | Linker offset относительно methods blob не равен публичному CAP key |
| `Instruction` | `offset`, `opcode`, `mnemonic`, `operands` | Offset от начала bytecode тела; branch targets уже абсолютные внутри метода |
| `ExceptionHandlerInfo` | start, active length, handler offset, catch index, stop bit | Перевод координат выполняет adapter JCVM |

Компонент имеет tag и u2 size; размер относится к info-части. `BinaryReader`
читает big-endian u1/u2/u4 и хранит курсор. Единого строгого bounds-check во всех
его операциях пока нет: `read_bytes` использует slice и может вернуть укороченные
данные. Поэтому проверки конкретных компонентов и downstream validation важны,
но не заменяют будущую общую валидацию бинарных границ.

## Последовательность разбора

1. `ZipReader` читает архив в память. `CAPContainer` выбирает пути с `/javacard/`
   и суффиксом `.cap`, проверяет обязательный набор.
2. Header определяет CAP version, package AID/version и optional package name.
3. Остальные `parse_from_bytes` получают эту версию и разбирают свой компонент.
4. `CAPFile.validate()` сейчас сверяет только размер Header с Directory.
5. `CAPFile.link()` вызывает `MethodComponent.link_with_descriptor`.
6. Linker последовательно читает headers и тела по bytecode_count из Descriptor.
   `methods_from_cap` затем сопоставляет offset/сигнатуры и проверяет согласованность.

Container индексирует компоненты по короткому имени. Несколько пакетов с одинаковыми
именами компонентов могут перезаписать друг друга: multi-package ZIP не является
поддержанным контрактом. `Applet.cap` не включён в `REQUIRED_COMPONENTS`, но builder
читает его безусловно; отсутствие приводит к ошибке, а не к поддержке library CAP.

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
| `container/zip_reader.py` | `ZipReader` | `list_files`, `read_file`, `read_all`; ZIP I/O, без интерпретации компонентов |
| `container/cap_container.py` | `CAPContainer` | Выбор компонентов, required-set, чтение по имени; debug hex-print не участвует в семантике |
| `model/cap_file.py` | `CAPFile`, `CAPFileBuilder` | Композиция parsers, validate/link; не переносить сюда lowering |
| `model/method_info.py` | `Instruction`, `Method`, `ExceptionHandler`, `parse_bytecode`, switch parsers | Таблица opcode/длины, signed/unsigned operands, method-local targets |
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
| `components/binary_reader.py` | `BinaryReader` | Курсор и big-endian primitives; bounds-контракт требует усиления |
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

Поддержанный сквозной путь использует обычные concrete method headers.
Вычисление offset extended header в linker содержит `...` вместо численной
длины; такая ветвь может упасть до явного отказа `methods_from_cap`. Abstract/native
и расширенные заголовки нельзя объявлять поддержанными на основании dataclass.

Таблица OPCODES шире семантического поднабора. Raw fallback некоторых operands
не эквивалентен нормализованным аргументам `lower()`; например, для новых immediate
и increment-форм нужно проверять signedness и число operands отдельно.
Switch-парсеры имеют собственные чтения и требуют негативных boundary-тестов.
В общем случае исключение может быть `ValueError`, `IndexError`, `struct.error`
или ошибка linker; единая иерархия binary parse errors ещё не введена.

## Как изменять

Новый компонент должен возвращать структурную модель и проверять потребление
payload. Версионную ветку следует выбирать по Header, не по Java-комментариям
или имени файла. Для новой инструкции одновременно меняются длина, структура
operands и тест method-local offsets. После parser-теста выполняется JCVM lowering:
он обнаруживает рассинхронизацию покрытия байткода.

Регрессии: [integration_tests/test_name1.py](../../integration_tests/test_name1.py),
в частности `BinaryBoundaryTests`, сравнение mnemonic/offset с JCA и CAP 2.1 fixture.
Нужны отдельные будущие тесты malformed components, extended headers, отсутствующего
Applet и collision компонентов нескольких пакетов. Изменение документации эти
дефекты не исправляет.
