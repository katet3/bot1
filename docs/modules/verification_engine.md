# verification_engine — структурные правила CFG

[К документации](../README.md) · [Фасад](../../verification_engine/verifier.py)

## Назначение и API

Рабочий публичный вызов — `Verifier().verify(method)`. Он сам строит CFG через
`cfg_generator.builder.build_cfg`, затем передаёт его в `RuleEngine.run(cfg)`.
Старое описание `VerificationEngine.verify(method, cfg)` не соответствует коду.
Чтобы проверить заранее созданный CFG, можно явно использовать `RuleEngine`;
готовый фасад `Verifier` такой параметр не принимает.

Проверка является набором структурных правил. Стек, типы значений, байтовое
покрытие метода и точное соответствие семантике переходов проверяются позднее
другими модулями. Этот пакет не сравнивает граф с внешним эталонным графом.

## Структура и поток данных

`RuleEngine` один раз строит `RuleContext`: block map, исходный edge list,
adjacency и reverse adjacency. Правило реализует `check(cfg, context)` и возвращает
список `VerificationError`. `VerificationReport` хранит success/errors, умеет
extend/merge и вывод в текст. Поле `severity` базового `Rule` сейчас не управляет
успехом отчёта: наличие добавленной ошибки делает success ложным.

| Модуль | Определения | Фактическое поведение |
| --- | --- | --- |
| `verifier.py` | `Verifier` | Регистрирует четыре правила и строит CFG |
| `engine/rule_base.py` | `Rule` | Абстрактный `check`, name, severity |
| `engine/rule_context.py` | `RuleContext` | Индексы, общие для всех правил |
| `engine/rule_engine.py` | `RuleEngine` | Построение context и последовательный запуск rules |
| `model/verification_error.py` | `VerificationError` | Тип ошибки называется `error_type`, плюс message и необязательные координаты |
| `model/verification_report.py` | `VerificationReport` | `add_error`, `extend`, `merge`, `has_errors`, `summary`, `to_text` |
| `rules/block/empty_block_rule.py` | `EmptyBlockRule` | Проверка непустых instructions |
| `rules/graph/reachability_rule.py` | `ReachabilityRule` | Единственная entry и BFS достижимости всех блоков |
| `rules/edge/edge_target_rule.py` | `EdgeTargetRule` | Проверка наличия source/target в block map |
| `rules/consistency/successor_rule.py` | `SuccessorConsistencyRule` | Сравнение множества block.successors с adjacency |
| `rules/block/overlap_rule.py` | Нет | Пустая заготовка; overlap не проверяется этим правилом |
| `rules/block/range_rule.py` | Нет | Пустая заготовка; range rule отсутствует |
| `rules/consistency/predecessor_rule.py` | Нет | Пустая заготовка; отдельная симметричная проверка predecessors отсутствует |
| `rules/edge/conditional_rule.py` | Нет | Пустая заготовка |
| `rules/edge/exit_rule.py` | Нет | Пустая заготовка |
| `rules/graph/entry_rule.py` | Нет | Пустая заготовка; часть проверки entry находится в ReachabilityRule |

SuccessorConsistency использует множества: он проверяет состав целей, но не
кратность рёбер и не различие TRUE/FALSE. Reachability включает рёбра context,
в том числе exceptional, если они построены upstream.

## Подтверждённый технический долг

Ошибочные входы не во всех случаях дают штатный `VerificationReport`:

1. Несколько правил создают `VerificationError(code=...)`, тогда как dataclass
   принимает `error_type`. Например, пустой блок приводит к `TypeError`.
2. `RuleEngine.run` вызывает `report.add_error(errors)` для списка. В результате
   `errors` отчёта может содержать вложенные списки; нужен согласованный вызов
   `extend` либо итерация отдельных элементов.
3. `_build_context` индексирует adjacency по концам рёбер до запуска EdgeTargetRule.
   Неверная цель/источник может вызвать `KeyError` раньше предназначенного правила.

Первые два поведения воспроизведены при подготовке документации. Они не исправлены
в документационном обновлении. Текущие 93 регрессии не являются покрытием всех
этих негативных ветвей. `report.success=True` означает отсутствие срабатывания
четырёх текущих правил, а не доказанную корректность произвольного CFG.

## Как добавлять правило

Наследуйте `Rule`, возвращайте список `VerificationError(error_type=..., message=...)`,
используйте готовый context и зарегистрируйте правило в `Verifier.__init__`.
До расширения набора следует исправить агрегацию и unsafe context construction,
иначе новый дефект будет замаскирован ошибкой отчётности.

Для каждого правила нужны корректный граф и минимальный граф-нарушитель.
Отдельно проверяются точный error_type, координаты, плоский errors list и то,
что вывод `to_text()` остаётся пригодным для главного CLI. При проверке source/target
порядок обработки должен гарантировать, что диагностика достижима на повреждённом
графе. Эти рекомендации описывают следующую работу, не существующий полный test suite.
