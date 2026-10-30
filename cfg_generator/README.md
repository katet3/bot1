# cfg_generator

`CFGGenerator.build` строит базовые блоки, обычные и исключительные рёбра.
Обработчики поступают как method-local `jcvm_ir.Handler` из `methods_from_cap`;
start/end/target проверяются и учитываются при разбиении. Стековую семантику
отдельно проверяет `jcvm_ir`.

Поддерживаются 32 условные формы, включая 16 `_w`, goto/switch/return и `athrow`.
После `athrow` обычного fallthrough нет; исключительные рёбра строятся по handlers.
`jsr/ret` явно отвергаются до построения блоков, поскольку их семантика не реализована.

Полная документация сопровождения: **[cfg_generator: архитектура, контракты и расширение](../docs/modules/cfg_generator.md)**.

- [Общая архитектура проекта](../docs/PROJECT.md)
- [Каталог каждого исходного модуля](../docs/SOURCE_MAP.md)
- [Архитектурные решения](../docs/DECISIONS.md)
- [Ограничения и технический долг](../docs/KNOWN_LIMITS.md)
- [Проверки и примеры](../docs/modules/testing_examples.md)

Регрессии D-04/D-05 (36 тестов, без angr/pysoot):

```powershell
.\.venv-angr10\Scripts\python.exe -m unittest discover -s cfg_generator/tests -p "test_*.py" -v
```

Редакция документации — 30 октября 2026 года, после исправления D-05.
