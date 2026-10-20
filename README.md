# Research проект реализации поддержки JavaCard applets для эмулятора angr

## Назначение проекта

Проект направлен на реализацию поддержки Java Card applets для среды анализа и символического исполнения angr.

Цель проекта — построение полноценного pipeline преобразования Java Card CAP-файлов в промежуточное представление, совместимое с Soot и angr, что позволит выполнять:

* symbolic execution;
* control-flow analysis;
* taint analysis;
* reachability analysis;
* vulnerability research;
* automatic reasoning over Java Card applications.

Проект ориентирован на Java Card CAP 3.0.5

## Общая архитектура проекта

Общая схема обработки:

```text
.cap file
    ↓
CAP decompile
    ↓
semantic model
    ↓
bytecode instructions
    ↓
CFG Generator
    ↓
CFG Verification
    ↓
JCVM IR
    ↓
JVM-like IR (semantic lifting)
    ↓
Soot IR (Jimple / Shimple)
    ↓
pysoot-compatible model
    ↓
angr Soot Engine
    ↓
Symbolic execution / analysis
```

## Архитектурные уровни

Проект построен как набор независимых аналитических модулей.

Каждый модуль имеет строго определённую ответственность и получает результат предыдущего этапа.

### 1. CAP Decompile

Отвечает за преобразование бинарного `.cap` контейнера в структурную модель Java Card VM.

Выполняет:

```text
CAP container
→ component parsing
→ structural model
→ bytecode extraction
```

Результат:

* полная типизированная модель CAP;
* извлечённые байткод-инструкции;
* декомпилированное представление методов.

### 2. CFG Generator

Генерирует Control Flow Graph (CFG) поверх декомпилированных инструкций.

Выполняет:

* поиск leaders;
* разбиение на Basic Blocks;
* построение control-flow edges;
* обработку branch-инструкций;
* switch transitions;
* exception flow.

Результат:

```text
method instructions
        ↓
basic blocks
        ↓
CFG
```

Поддерживаются:

* FALLTHROUGH
* CONDITIONAL\_TRUE
* CONDITIONAL\_FALSE
* GOTO
* SWITCH
* RETURN
* EXCEPTION

Также поддерживается визуализация CFG.

### 3. Verification Engine

Проверяет корректность построенного CFG.

Сравнивает:

```text
CFG Generator output
vs
reference graph
```

Проверяются:

* корректность разбиения на блоки;
* совпадение инструкций;
* совпадение successors;
* корректность переходов.

Результат:

```python
VerificationReport
```

Позволяет обнаруживать:

* потерянные блоки;
* лишние блоки;
* неверные переходы;
* ошибки в control flow.

Модуль предназначен для regression testing и CI.

### 4. JCVM IR (Planned)

Промежуточное представление Java Card VM.

Будет выполнять:

* нормализацию инструкций JCVM;
* унификацию stack semantics;
* подготовку к semantic lifting.

Представление будет ближе к low-level VM model.

### 5. JVM-like IR (Semantic Lifting)

Преобразует стековую модель Java Card в JVM-подобное представление.

Выполняет:

* stack elimination;
* temporary variable insertion;
* normalization of expressions;
* structured control flow preparation.

Пример:

До:

```text
sload_1
sload_2
sadd
```

После:

```text
tmp0 = local1 + local2
```

### 6. Soot IR

Преобразование в представление, совместимое с Soot.

Целевые форматы:

* Jimple
* Shimple

Подготавливается:

* typed locals;
* statements;
* method body;
* CFG-preserving IR.

### 7. pysoot-compatible model

Построение модели, совместимой с pysoot.

Позволяет использовать существующую инфраструктуру Soot внутри angr.

### 8. angr Soot Engine

Интеграция с angr.

Предполагаемые возможности:

* symbolic execution;
* path exploration;
* state reasoning;
* symbolic constraints;
* vulnerability analysis.

# CAP Decompile

## Назначение

CAP — Converted Applet.

Формат описывается в Java Card VM Specification.

CAP decompile — модуль, преобразующий бинарный `.cap` контейнер в полную структурную модель Java Card без семантической интерпретации.

Модуль:

* открывает `.cap`;
* извлекает компоненты;
* парсит структуру;
* строит типизированную модель;
* извлекает bytecode methods.

Поддерживается Java Card CAP 3.0.5.

## Pipeline CAP decompile

```text
.cap
    ↓
ZIP container
    ↓
CAP components
    ↓
typed component models
    ↓
CAPFile
    ↓
bytecode instructions
```

## Container Layer

Отвечает за:

* открытие `.cap` как ZIP;
* извлечение компонентов;
* чтение raw bytes;
* управление контейнером.

## Component Parsing Layer

Каждый компонент парсится независимо.

Поддерживаемые компоненты:

* Header
* Directory
* Import
* Applet
* ConstantPool
* Class
* Method
* StaticField
* RefLocation
* Descriptor

Каждый компонент:

* получает `bytes`;
* парсится независимо;
* возвращает типизированную модель;
* не взаимодействует напрямую с другими компонентами.

## Structural Model Layer

Результат — единая модель:

```python
class CAPFile:
    header: HeaderComponent
    directory: DirectoryComponent
    imports: ImportComponent
    applet: AppletComponent
    constant_pool: ConstantPoolComponent
    classes: ClassComponent
    methods: MethodComponent
    static_fields: StaticFieldComponent
    ref_locations: RefLocationComponent
    descriptor: DescriptorComponent
```

## Validation Layer (TODO)

Проверяет:

* корректность размеров;
* корректность offsets;
* соответствие Directory;
* согласованность Class ↔ Method;
* dangling references.

# CFG Generator

## Назначение

`cfg_generator` строит граф потока управления поверх декомпилированных инструкций метода.

Выполняет:

* поиск leaders;
* построение Basic Blocks;
* построение CFG edges;
* обработку branch instructions;
* switch analysis;
* exception transitions.

## Визуализация CFG

Поддерживаются:

### ASCII visualization

Текстовое представление для отладки.

Пример:

```text
[B0]
0:aload_0
1:ifeq 20

 ├──TRUE──> B2
 └──FALSE─> B1
```

### Graphviz visualization

Используется Python-библиотека:

```bash
pip install graphviz
```

Также необходимо установить Graphviz Software и добавить его в PATH.

После установки должна работать команда:

```bash
dot -V
```

Пример:

```python
from cfg_generator.visualization.dot_exporter import (
    DotExporter
)

DotExporter().export(
    cfg,
    output_path="cfg_method",
    format="png"
)
```

Результат:

```text
cfg_method.png
```

# Verification Engine

## Назначение

`verification_engine` выполняет автоматическую проверку корректности CFG.

Сравниваются:

* blocks;
* instructions;
* edges.

Результат:

```python
VerificationReport
```

## Использование

```python
from verification_engine.verifier import (
    VerificationEngine
)

verifier = VerificationEngine()

report = verifier.verify(
    method,
    cfg
)

print(report.success)

for error in report.errors:
    print(error)
```

## Использование в CI

```python
assert report.success
```

Позволяет обнаруживать регрессии в CFG generation.

# Структура проекта

```text
project/
├── cap_decompile/
├── cfg_generator/
├── verification_engine/
├── jcvm_ir/
├── jvm_like_ir/
├── soot_ir/
├── pysoot_adapter/
└── angr_integration/
```

# Ограничения текущей версии

Текущая реализация:

* ориентирована на Java Card CAP 3.0.5;
* работает поверх декомпилированных инструкций;
* не анализирует CAP бинарно после decompile stage;
* не завершает semantic lifting;
* находится в стадии активной разработки.

# Планируемые расширения

Планируются:

* dominator tree;
* SSA preparation;
* loop analysis;
* taint analysis;
* symbolic execution;
* Jimple generation;
* Shimple generation;
* angr integration;
* automatic regression verification.
