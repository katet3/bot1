# cap_decompile

CAPContainer и CAPFileBuilder читают бинарные компоненты и связывают методы с Descriptor.
Для typed pipeline равнозначны `jcvm_ir.methods_from_cap(cap)` и `cap.to_model()`:
после D-07 оба возвращают `list[MethodInput]` с заголовком, сигнатурой, static flag
и method-local обработчиками. Старый неполный `Method` больше не создаётся.
Смена типа результата и координат описана в руководстве подсистемы.

После D-06 linker читает обычный двухбайтовый и расширенный четырёхбайтовый
заголовок; смещение метода сохраняется до чтения заголовка относительно methods blob.
Усечённые header/body отклоняются явно. Typed pipeline по-прежнему принимает
только ordinary concrete methods: чтение extended header не включает его lowering.

После D-08 все чтения BinaryReader требуют полный диапазон и сохраняют курсор
при отказе. Декодер использует явные форматы операндов; raw fallback удалён.
Исправлены размеры lookup-switch, wide increments и stack instructions с `mn`.
Ошибки диапазона/декодирования — `BinaryParseError`, подкласс `ValueError`.

Проверки из корня проекта (64 теста D-06–D-08, без angr/pysoot):

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest discover -s cap_decompile/tests -p "test_*.py" -v
```

Полная документация сопровождения: **[cap_decompile: архитектура, контракты и расширение](../docs/modules/cap_decompile.md)**.

- [Общая архитектура проекта](../docs/PROJECT.md)
- [Каталог каждого исходного модуля](../docs/SOURCE_MAP.md)
- [Архитектурные решения](../docs/DECISIONS.md)
- [Ограничения и технический долг](../docs/KNOWN_LIMITS.md)
- [Проверки и примеры](../docs/modules/testing_examples.md)

Редакция документации — 30 октября 2026 года, после исправления D-08.
