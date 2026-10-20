# Verification Engine

## Назначение

`verification_engine` — модуль автоматической верификации корректности построенного Control Flow Graph (CFG).

Модуль анализирует граф потока управления, сформированный компонентом `cfg_generator`, и проверяет его на соответствие набору формальных инвариантов.

Основная цель — выявление ошибок построения CFG, возникающих при:

* определении лидеров базовых блоков;
* разбиении инструкций на блоки;
* построении рёбер управления;
* обработке условных переходов;
* обработке инструкций switch;
* формировании таблиц successors и predecessors.

В отличие от подхода, основанного на сравнении двух графов, данный модуль проверяет корректность одного CFG с помощью независимых правил верификации.

Это позволяет использовать верификатор:

* во время разработки CFG-генератора;
* в автоматических тестах;
* в пайплайнах CI/CD;
* при анализе неизвестных CAP-файлов.



# Место в архитектуре проекта

Модуль является завершающим этапом анализа байт-кода.

```text
CAP-файл
    ↓
cap_decompile
    ↓
Method / Instruction
    ↓
cfg_generator
    ↓
Control Flow Graph (CFG)
    ↓
verification_engine
    ↓
VerificationReport
```

`verification_engine` не работает с бинарным CAP-файлом напрямую и использует исключительно модель CFG, сформированную компонентом `cfg_generator`.



# Основная идея

Верификатор реализован по принципу Rule Engine.

Каждое правило представляет собой независимую проверку одного инварианта CFG.

Например:

* блок не должен быть пустым;
* все блоки должны быть достижимы;
* все рёбра должны ссылаться на существующие блоки;
* список successors должен совпадать с набором исходящих рёбер.

Каждое правило работает независимо от остальных и возвращает список обнаруженных ошибок.

Такой подход обеспечивает:

* простое расширение системы;
* изоляцию проверок;
* повторное использование контекста анализа;
* минимальные изменения при добавлении новых проверок.



# Структура модуля

```text
verification_engine/
│
├── verifier.py
│
├── engine/
│   ├── rule_base.py
│   ├── rule_context.py
│   └── rule_engine.py
│
├── rules/
│   ├── block/
│   │   ├── empty_block_rule.py
│   │   ├── block_range_rule.py
│   │   └── overlap_rule.py
│   │
│   ├── edge/
│   │   ├── edge_target_rule.py
│   │   ├── conditional_edge_rule.py
│   │   └── exit_edge_rule.py
│   │
│   ├── graph/
│   │   ├── entry_rule.py
│   │   ├── exit_rule.py
│   │   └── reachability_rule.py
│   │
│   └── consistency/
│       ├── successor_rule.py
│       └── predecessor_rule.py
│
└── model/
    ├── verification_error.py
    └── verification_report.py
```



# Архитектура Rule Engine

## Rule

Базовый абстрактный класс для всех проверок.

Каждое правило реализует метод:

```python
check(cfg, context)
```

который возвращает:

```python
list[VerificationError]
```

Пустой список означает успешное прохождение проверки.



## RuleContext

Перед запуском правил создаётся общий контекст анализа.

Контекст содержит предварительно вычисленные структуры данных, используемые всеми правилами.

### block\_map

Отображение:

```python
block.id -> BasicBlock
```

Используется для быстрого поиска блоков.



### adjacency

Прямой граф переходов.

```python
source_block_id -> [target_ids]
```

Используется при обходах CFG.



### reverse\_adjacency

Обратный граф переходов.

```python
target_block_id -> [source_ids]
```

Используется при проверке predecessors.



### edge\_list

Список всех рёбер CFG.



## RuleEngine

RuleEngine управляет выполнением правил.

Последовательность работы:

1. создаётся RuleContext;
2. правила выполняются поочерёдно;
3. найденные ошибки агрегируются;
4. формируется VerificationReport.



# Реализованные правила

## EmptyBlockRule

Проверяет, что каждый базовый блок содержит хотя бы одну инструкцию.

Ошибка:

```text
EMPTY_BLOCK
Block B5 is empty
```

Подобная ситуация обычно указывает на ошибку выделения лидеров или формирования границ блока.



## EntryRule

Проверяет наличие ровно одного входного блока.

Допустимо:

```text
1 entry block
```

Ошибки:

```text
Missing entry block
```

или

```text
Multiple entry blocks
```



## ExitRule

Проверяет наличие хотя бы одного выходного блока.

Ошибка:

```text
CFG has no exit block
```



## EdgeTargetRule

Проверяет корректность всех рёбер CFG.

Для каждого ребра должны существовать:

* source блок;
* target блок.

Ошибка:

```text
INVALID_EDGE_TARGET
B3 -> B100
```



## ConditionalEdgeRule

Проверяет корректность условных переходов.

Для блока, завершающегося условной инструкцией:

```text
if*
```

должно существовать:

```text
1 CONDITIONAL_TRUE
1 CONDITIONAL_FALSE
```



## ExitEdgeRule

Проверяет отсутствие исходящих рёбер у выходных блоков.

Ошибка:

```text
EXIT_HAS_SUCCESSORS
```



## ReachabilityRule

Проверяет достижимость всех блоков из входного блока.

Алгоритм:

```text
BFS(entry)
```

или

```text
DFS(entry)
```

После обхода все блоки должны оказаться посещёнными.

Ошибка:

```text
UNREACHABLE_BLOCK
Block B7 is unreachable
```

Недостижимые блоки обычно возникают при:

* пропущенных лидерах;
* потерянных переходах;
* ошибках обработки switch.



## SuccessorConsistencyRule

Сравнивает:

```python
block.successors
```

и

```python
cfg.edges
```

Для каждого блока множество successors должно совпадать с множеством целей исходящих рёбер.

Ошибка:

```text
SUCCESSOR_MISMATCH
Block B4:
expected {7, 8}
actual {7}
```



## PredecessorConsistencyRule

Проверяет обратную связь графа.

Если существует ребро:

```text
B3 -> B5
```

то блок B5 обязан содержать:

```python
predecessors = [3]
```

Ошибка:

```text
PREDECESSOR_MISMATCH
```



# Процесс верификации

Метод:

```python
Verifier.verify(method)
```

выполняет следующие действия:

### 1. Построение CFG

```python
cfg = build_cfg(method)
```



### 2. Формирование контекста

Создаётся RuleContext с предварительно вычисленными индексами.



### 3. Выполнение правил

RuleEngine запускает зарегистрированные правила.

```python
for rule in rules:
    errors.extend(
        rule.check(cfg, context)
    )
```



### 4. Формирование отчёта

Все ошибки агрегируются в VerificationReport.



# Модель ошибки

Каждая ошибка представляется объектом:

```python
VerificationError
```

Поля:

```python
code
message
severity
```

Пример:

```python
VerificationError(
    code="UNREACHABLE_BLOCK",
    message="Block B6 is unreachable"
)
```



# Отчёт о верификации

Результат работы верификатора представлен объектом:

```python
VerificationReport
```

Основные поля:

```python
errors
```

Список найденных ошибок.

Метод:

```python
is_valid()
```

возвращает:

```python
True
```

если ошибок не обнаружено.



# Пример использования

```python
from verification_engine.verifier import Verifier

verifier = Verifier()

for method in methods:

    report = verifier.verify(method)

    if report.is_valid():

        print(
            f"{method.token}: OK"
        )

    else:

        print(
            f"{method.token}: FAILED"
        )

        for error in report.errors:

            print(
                f"{error.code}: "
                f"{error.message}"
            )
```



# Расширяемость

Rule Engine позволяет добавлять новые проверки без изменения ядра системы.

Для добавления нового правила необходимо:

1. создать класс-наследник `Rule`;
2. реализовать метод `check()`;
3. зарегистрировать правило в `RuleEngine`.

Пример:

```python
class SwitchTargetRule(Rule):

    def check(self, cfg, context):
        ...
```



# Возможные расширения

### SwitchTargetRule

Проверка того, что каждая цель:

```text
stableswitch
itableswitch
slookupswitch
```

начинается с лидера базового блока.



### OffsetMappingRule

Проверка согласованности:

```python
cfg.offset_to_block
```

и реального множества блоков.



### ExceptionHandlerRule

Проверка корректности рёбер обработчиков исключений.



### LoopStructureRule

Анализ циклов и обратных рёбер CFG.



### DominatorRule

Проверка дерева доминаторов и структурной корректности графа.



### StackSafetyRule

Проверка согласованности глубины операндного стека на всех путях выполнения.



# Ограничения текущей версии

* выполняется проверка только одного CFG;
* отсутствует сравнение с эталонным графом;
* не анализируется бинарный CAP-файл напрямую;
* не проверяется корректность декомпиляции инструкций;
* не выполняется семантический анализ байт-кода;
* межпроцедурный анализ не поддерживается;
* анализ ограничен графом управления отдельного метода;
* корректность инструкций и операндов предполагается обеспеченной модулем `cap_decompile`.

Такое разделение ответственности позволяет использовать `verification_engine` исключительно для проверки структурной корректности CFG и упрощает его интеграцию в остальные компоненты системы.
