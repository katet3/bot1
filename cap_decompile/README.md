# cap_decompile

CAPContainer и CAPFileBuilder читают бинарные компоненты и связывают методы с Descriptor. Для typed pipeline методы извлекаются через jcvm_ir.methods_from_cap.

После D-06 linker читает обычный двухбайтовый и расширенный четырёхбайтовый
заголовок; смещение метода сохраняется до чтения заголовка относительно methods blob.
Усечённые header/body отклоняются явно. Typed pipeline по-прежнему принимает
только ordinary concrete methods: чтение extended header не включает его lowering.

Проверки из корня проекта (16 тестов, без angr/pysoot):

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest discover -s cap_decompile/tests -p "test_*.py" -v
```

Полная документация сопровождения: **[cap_decompile: архитектура, контракты и расширение](../docs/modules/cap_decompile.md)**.

- [Общая архитектура проекта](../docs/PROJECT.md)
- [Каталог каждого исходного модуля](../docs/SOURCE_MAP.md)
- [Архитектурные решения](../docs/DECISIONS.md)
- [Ограничения и технический долг](../docs/KNOWN_LIMITS.md)
- [Проверки и примеры](../docs/modules/testing_examples.md)

Редакция документации — 30 октября 2026 года, после исправления D-06.
