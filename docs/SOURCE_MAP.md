# Каталог всех Python-модулей

[К документации](README.md) · [Архитектура](PROJECT.md)

Исходный каталог охватывал **107 файлов Python**, включая 6 тестовых модулей и 14 пустых
файлов. Для каждого указаны назначение, определения и профильное руководство.
Это справочник исходных модулей; подробные контракты, инварианты и порядок
изменений находятся в связанных руководствах. Состав определений извлечён из AST
этого снимка, описания ответственности сверены с реализацией. Private helpers
не становятся публичным API от присутствия в каталоге.

Дополнение D-04: ниже актуализирован раздел CFG и добавлен `analysis/handlers.py`.
Регрессии находятся в `cfg_generator/tests/__init__.py` (маркер пакета),
`test_exception_handlers.py` (14 проверок границ и графа) и `test_handler_pipeline.py`
(3 проверки контрактов IR). Число 107 и `source_snapshot.json` относятся к исходному
снимку, а не к текущему дереву после исправлений D-01–D-06.
Дополнение D-05: обновлены classifier, leaders и edge builder; добавлен
`cfg_generator/tests/test_control_flow.py` — 19 регрессий control flow и согласования IR.
Дополнение D-06: исправлены размеры method headers и фиксация blob offset в linker;
добавлены `cap_decompile/tests/__init__.py` и `test_method_headers.py` — 16 регрессий.

## main.py

### `main.py`

Композиция CAP→IR→pysoot→angr; CLI, режимы остановки, экспорт и итоговая диагностика.

[Исходник](../main.py) · [Руководство](modules/main.md)

Определения: `load_cap()`; `extract_methods()`; `build_cfgs()`; `verify_methods()`; `build_jcvm_ir()`; `build_jvm_like_ir()`; `load_symbols()`; `build_soot_ir()`; `build_pysoot_model()`; `load_angr_program()`; `export_ir_methods()`; `export_soot_ir()`; `export_cfgs()`; `print_debug_output()`; `parse_args()`; `main()`.

## cap_decompile

### `cap_decompile/__init__.py`

Пустой маркер пакета; публичного фасада здесь нет.

[Исходник](../cap_decompile/__init__.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cap_decompile/components/applet.py`

Applet AID и offset install; регистрация объектов здесь не выполняется.

[Исходник](../cap_decompile/components/applet.py) · [Руководство](modules/cap_decompile.md)

Определения: `AppletInfo`; `AppletComponent` — `parse_from_bytes()`.

### `cap_decompile/components/base.py`

Общие tag/size компонентной dataclass-модели.

[Исходник](../cap_decompile/components/base.py) · [Руководство](modules/cap_decompile.md)

Определения: `CAPComponent` — `parse_from_bytes()`.

### `cap_decompile/components/binary_reader.py`

Big-endian чтение и курсор; bounds-контракт пока неоднороден.

[Исходник](../cap_decompile/components/binary_reader.py) · [Руководство](modules/cap_decompile.md)

Определения: `BinaryReader` — `read_u1()`, `read_u2()`, `read_u4()`, `read_bytes()`, `remaining()`, `tell()`, `seek()`, `skip()`.

### `cap_decompile/components/class_component.py`

Class/signature pool, hierarchy, interfaces и info-relative offsets.

[Исходник](../cap_decompile/components/class_component.py) · [Руководство](modules/cap_decompile.md)

Определения: `ClassRef`; `parse_class_ref()`; `TypeDescriptor`; `parse_type_descriptor()`; `InterfaceInfo`; `parse_interface_info()`; `ImplementedInterfaceInfo`; `parse_implemented_interface()`; `RemoteMethodInfo`; `RemoteInterfaceInfo`; `parse_remote_interface_info()`; `ClassInfo`; `parse_class_info()`; `ClassComponent` — `parse_from_bytes()`.

### `cap_decompile/components/constant_pool.py`

Структуры class/field/method refs и внутренние/external идентификаторы.

[Исходник](../cap_decompile/components/constant_pool.py) · [Руководство](modules/cap_decompile.md)

Определения: `CPInfo`; `ConstantClassref`; `parse_classref()`; `ConstantFieldOrMethodRef`; `parse_field_or_method()`; `ConstantStaticRef`; `parse_static_ref()`; `ConstantPoolComponent` — `parse_from_bytes()`.

### `cap_decompile/components/descriptor.py`

Декларации классов/полей/методов, counts и raw type descriptors.

[Исходник](../cap_decompile/components/descriptor.py) · [Руководство](modules/cap_decompile.md)

Определения: `FieldRef`; `FieldDescriptorInfo`; `MethodDescriptorInfo`; `ClassDescriptorInfo`; `TypeDescriptorInfo`; `DescriptorComponent` — `parse_from_bytes()`.

### `cap_decompile/components/directory.py`

Version-aware component sizes, counts и custom component metadata.

[Исходник](../cap_decompile/components/directory.py) · [Руководство](modules/cap_decompile.md)

Определения: `StaticFieldSizeInfo`; `CustomComponentInfo`; `DirectoryComponent` — `parse_from_bytes()`.

### `cap_decompile/components/header.py`

Magic, CAP version, package AID/version/name и основные проверки заголовка.

[Исходник](../cap_decompile/components/header.py) · [Руководство](modules/cap_decompile.md)

Определения: `CAPVersion` — `major()`, `minor()`, `from_numbers()`; `PackageInfo`; `HeaderComponent` — `parse_from_bytes()`.

### `cap_decompile/components/import_component.py`

Упорядоченные imports, на которые ссылается package token.

[Исходник](../cap_decompile/components/import_component.py) · [Руководство](modules/cap_decompile.md)

Определения: `PackageInfo`; `ImportComponent` — `parse_from_bytes()`.

### `cap_decompile/components/method_component.py`

Handler table, заголовки размером 2/4 байта и последовательный linking с Descriptor.
Blob offset фиксируется до header; усечённые header/body отклоняются, список методов
заменяется только после полного успеха. Typed adapter не допускает extended methods.

[Исходник](../cap_decompile/components/method_component.py) · [Руководство](modules/cap_decompile.md)

Определения: `ExceptionHandlerInfo`; `MethodHeaderInfo`; `ExtendedMethodHeaderInfo`; `MethodInfo`; `MethodComponent` — `parse_from_bytes()`, `link_with_descriptor()`, `_parse_method_header()`.

### `cap_decompile/tests/__init__.py`

Маркер пакета регрессионных тестов CAP parser/linker.

[Исходник](../cap_decompile/tests/__init__.py) · [Руководство](modules/testing_examples.md)

### `cap_decompile/tests/test_method_headers.py`

16 проверок форматов headers, blob offsets, handler prefix, malformed lengths,
повторной линковки, отсутствия частичного результата и границы typed adapter.
Бинарный ordinary Method component с обработчиком проходит до Soot.

[Исходник](../cap_decompile/tests/test_method_headers.py) · [Руководство](modules/cap_decompile.md)

Определения: helpers `component()`, `descriptor()`, `cap_for()`; тестовый класс
`MethodHeaderTests`.

### `cap_decompile/components/reference_location.py`

Бинарные сведения о расположениях ссылок CAP.

[Исходник](../cap_decompile/components/reference_location.py) · [Руководство](modules/cap_decompile.md)

Определения: `ReferenceLocationComponent` — `parse_from_bytes()`.

### `cap_decompile/components/static_field.py`

Начальный static image и array initializers; не runtime storage.

[Исходник](../cap_decompile/components/static_field.py) · [Руководство](modules/cap_decompile.md)

Определения: `ArrayInitInfo` — `element_size()`, `element_count()`; `StaticFieldComponent` — `parse_from_bytes()`.

### `cap_decompile/container/cap_container.py`

Отбор /javacard/*.cap, обязательные компоненты и доступ по короткому имени.

[Исходник](../cap_decompile/container/cap_container.py) · [Руководство](modules/cap_decompile.md)

Определения: `CAPContainer` — `load()`, `get_component()`, `list_components()`, `print_component()`, `print_components()`.

### `cap_decompile/container/zip_reader.py`

Чтение ZIP без интерпретации бинарного формата.

[Исходник](../cap_decompile/container/zip_reader.py) · [Руководство](modules/cap_decompile.md)

Определения: `ZipReader` — `list_files()`, `read_file()`, `read_all()`.

### `cap_decompile/main.py`

Исторический debug script с локальными импортами; не основной CLI.

[Исходник](../cap_decompile/main.py) · [Руководство](modules/cap_decompile.md)

Определения: `main()`.

### `cap_decompile/model/cap_file.py`

Сборка CAPFile, ограниченная validate/link и legacy to_model.

[Исходник](../cap_decompile/model/cap_file.py) · [Руководство](modules/cap_decompile.md)

Определения: `CAPFile` — `validate()`, `link()`, `to_model()`; `CAPFileBuilder` — `build()`.

### `cap_decompile/model/constant_pool_entries.py`

Пустая заготовка; CP определения находятся в components/constant_pool.py.

[Исходник](../cap_decompile/model/constant_pool_entries.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cap_decompile/model/method_info.py`

Instruction/Method и opcode decoder; branch operands становятся method-local targets.

[Исходник](../cap_decompile/model/method_info.py) · [Руководство](modules/cap_decompile.md)

Определения: `Instruction`; `ExceptionHandler`; `Method`; `read_u1()`; `read_s1()`; `read_u2()`; `read_s2()`; `read_u4()`; `read_s4()`; `parse_stableswitch()`; `parse_itableswitch()`; `parse_slookupswitch()`; `parse_ilookupswitch()`; `parse_bytecode()`.

### `cap_decompile/model/references.py`

Пустая заготовка; семантическая Reference определена в jcvm_ir.

[Исходник](../cap_decompile/model/references.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cap_decompile/parser.py`

Пустая заготовка; реальный вход — CAPContainer и CAPFileBuilder.

[Исходник](../cap_decompile/parser.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cap_decompile/validation/invariants.py`

Пустая заготовка общих инвариантов CAP.

[Исходник](../cap_decompile/validation/invariants.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cap_decompile/validation/validator.py`

Пустая заготовка общего структурного валидатора.

[Исходник](../cap_decompile/validation/validator.py) · [Руководство](modules/cap_decompile.md)

Определений классов/функций верхнего уровня нет; файл пуст.

## cfg_generator

### `cfg_generator/__init__.py`

Пустой маркер пакета.

[Исходник](../cfg_generator/__init__.py) · [Руководство](modules/cfg_generator.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cfg_generator/analysis/block_splitter.py`

Разбиение потока на блоки с последовательными IDs.

[Исходник](../cfg_generator/analysis/block_splitter.py) · [Руководство](modules/cfg_generator.md)

Определения: `split_basic_blocks()`; `_build_block()`.

### `cfg_generator/analysis/edge_builder.py`

Обычные рёбра, successors/predecessors; switch cases могут иметь общую цель.

[Исходник](../cfg_generator/analysis/edge_builder.py) · [Руководство](modules/cfg_generator.md)

Определения: `build_edges()`; `_add_edge()`.

### `cfg_generator/analysis/exception_edges.py`

Консервативные exception edges по method-local handlers; проверка разбиения до
изменения блоков, сохранение порядка и кратности.

[Исходник](../cfg_generator/analysis/exception_edges.py) · [Руководство](modules/cfg_generator.md)

Определения: `build_exception_edges()`.

### `cfg_generator/analysis/handlers.py`

Общая проверка method-local диапазонов и целей; чтение Handler либо явного legacy
Mapping, отказ от сырых CAP-координат без adapter.

[Исходник](../cfg_generator/analysis/handlers.py) · [Руководство](modules/cfg_generator.md)

Определения: `ExceptionRegion`; `validated_exception_regions()`.

### `cfg_generator/analysis/leaders.py`

Поиск целей, инструкций после всех terminators, границ защищённых диапазонов
и входов handlers; ранний отказ для unsupported `jsr/ret`.

[Исходник](../cfg_generator/analysis/leaders.py) · [Руководство](modules/cfg_generator.md)

Определения: `find_leaders()`.

### `cfg_generator/builder.py`

Композиция leaders/blocks/edges, entry/exit и offset map.

[Исходник](../cfg_generator/builder.py) · [Руководство](modules/cfg_generator.md)

Определения: `build_cfg()`.

### `cfg_generator/exporter.py`

Пустая заготовка; рабочие exporters в visualization.

[Исходник](../cfg_generator/exporter.py) · [Руководство](modules/cfg_generator.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `cfg_generator/generator.py`

Фасад CFGGenerator.build над build_cfg.

[Исходник](../cfg_generator/generator.py) · [Руководство](modules/cfg_generator.md)

Определения: `CFGGenerator` — `build()`.

### `cfg_generator/model/basic_block.py`

Инструкции и флаги блока; end_offset — начало последней инструкции.

[Исходник](../cfg_generator/model/basic_block.py) · [Руководство](modules/cfg_generator.md)

Определения: `BasicBlock`.

### `cfg_generator/model/cfg.py`

Граф метода и mapping начал блоков.

[Исходник](../cfg_generator/model/cfg.py) · [Руководство](modules/cfg_generator.md)

Определения: `CFG`.

### `cfg_generator/model/edge.py`

EdgeType и пара IDs концов ребра.

[Исходник](../cfg_generator/model/edge.py) · [Руководство](modules/cfg_generator.md)

Определения: `EdgeType`; `CFGEdge`.

### `cfg_generator/utils/instruction_utils.py`

Общие предикаты для 32 условных форм, goto/switch/return/throw; отдельный отказ
для decoded `jsr/ret`, не имеющих модели return-address.

[Исходник](../cfg_generator/utils/instruction_utils.py) · [Руководство](modules/cfg_generator.md)

Определения: `is_conditional_branch()`; `is_unconditional_branch()`; `is_switch()`;
`is_return()`; `is_throw()`; `is_terminator()`; `reject_unsupported_control_flow()`.

### `cfg_generator/visualization/ascii_exporter.py`

Текстовый CFG для отладки без Graphviz.

[Исходник](../cfg_generator/visualization/ascii_exporter.py) · [Руководство](modules/cfg_generator.md)

Определения: `ASCIIExporter` — `export()`.

### `cfg_generator/visualization/dot_exporter.py`

Graphviz exporter; для rendering нужен системный dot.

[Исходник](../cfg_generator/visualization/dot_exporter.py) · [Руководство](modules/cfg_generator.md)

Определения: `DotExporter` — `export()`.

## verification_engine

### `verification_engine/engine/rule_base.py`

Абстрактный контракт check(cfg,context) и metadata правила.

[Исходник](../verification_engine/engine/rule_base.py) · [Руководство](modules/verification_engine.md)

Определения: `Rule` — `check()`.

### `verification_engine/engine/rule_context.py`

Block/edge indexes и обе adjacency для правил.

[Исходник](../verification_engine/engine/rule_context.py) · [Руководство](modules/verification_engine.md)

Определения: `RuleContext`.

### `verification_engine/engine/rule_engine.py`

Context construction и запуск правил; aggregation имеет известный дефект.

[Исходник](../verification_engine/engine/rule_engine.py) · [Руководство](modules/verification_engine.md)

Определения: `RuleEngine` — `run()`.

### `verification_engine/model/verification_error.py`

Структурная ошибка с error_type, сообщением и необязательными координатами.

[Исходник](../verification_engine/model/verification_error.py) · [Руководство](modules/verification_engine.md)

Определения: `VerificationError`.

### `verification_engine/model/verification_report.py`

Success/errors, add/extend/merge и текстовый отчёт.

[Исходник](../verification_engine/model/verification_report.py) · [Руководство](modules/verification_engine.md)

Определения: `VerificationReport` — `add_error()`, `extend()`, `merge()`, `has_errors()`, `summary()`, `to_text()`.

### `verification_engine/rules/block/empty_block_rule.py`

Проверка пустых блоков; error constructor пока использует неверный keyword.

[Исходник](../verification_engine/rules/block/empty_block_rule.py) · [Руководство](modules/verification_engine.md)

Определения: `EmptyBlockRule` — `check()`.

### `verification_engine/rules/block/overlap_rule.py`

Пустая заготовка, правило не реализовано и не зарегистрировано.

[Исходник](../verification_engine/rules/block/overlap_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/block/range_rule.py`

Пустая заготовка, правило не реализовано и не зарегистрировано.

[Исходник](../verification_engine/rules/block/range_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/consistency/predecessor_rule.py`

Пустая заготовка симметричной проверки predecessors.

[Исходник](../verification_engine/rules/consistency/predecessor_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/consistency/successor_rule.py`

Проверяет множество successors, не кратность и типы рёбер.

[Исходник](../verification_engine/rules/consistency/successor_rule.py) · [Руководство](modules/verification_engine.md)

Определения: `SuccessorConsistencyRule` — `check()`.

### `verification_engine/rules/edge/conditional_rule.py`

Пустая заготовка conditional-edge правила.

[Исходник](../verification_engine/rules/edge/conditional_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/edge/edge_target_rule.py`

Проверяет существование концов рёбер; часть bad edges падает раньше в context.

[Исходник](../verification_engine/rules/edge/edge_target_rule.py) · [Руководство](modules/verification_engine.md)

Определения: `EdgeTargetRule` — `check()`.

### `verification_engine/rules/edge/exit_rule.py`

Пустая заготовка exit-rule.

[Исходник](../verification_engine/rules/edge/exit_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/graph/entry_rule.py`

Пустая заготовка; entry частично проверяется ReachabilityRule.

[Исходник](../verification_engine/rules/graph/entry_rule.py) · [Руководство](modules/verification_engine.md)

Определений классов/функций верхнего уровня нет; файл пуст.

### `verification_engine/rules/graph/reachability_rule.py`

Проверяет единственную entry и BFS-достижимость блоков.

[Исходник](../verification_engine/rules/graph/reachability_rule.py) · [Руководство](modules/verification_engine.md)

Определения: `ReachabilityRule` — `check()`.

### `verification_engine/verifier.py`

Четыре зарегистрированных правила; самостоятельно строит CFG.

[Исходник](../verification_engine/verifier.py) · [Руководство](modules/verification_engine.md)

Определения: `Verifier` — `verify()`.

## jcvm_ir

### `jcvm_ir/__init__.py`

Публичные реэкспорты типов, adapter, resolver и builder.

[Исходник](../jcvm_ir/__init__.py) · [Руководство](modules/jcvm_ir.md)

Определений классов/функций верхнего уровня нет; назначение — реэкспорты/константы.

### `jcvm_ir/adapter.py`

Восстанавливает MethodInput из CAP/Descriptor, signatures/slots и local handler offsets.

[Исходник](../jcvm_ir/adapter.py) · [Руководство](modules/jcvm_ir.md)

Определения: `MethodInput`; `methods_from_cap()`.

### `jcvm_ir/builder.py`

Проверяет покрытие bytes, нормализует CFG и выполняет stack dataflow.

[Исходник](../jcvm_ir/builder.py) · [Руководство](modules/jcvm_ir.md)

Определения: `IRBuilder` — `build()`.

### `jcvm_ir/lowering.py`

Нормализация Instruction в Operation и точную длину, pops/pushes/targets.

[Исходник](../jcvm_ir/lowering.py) · [Руководство](modules/jcvm_ir.md)

Определения: `lower()`.

### `jcvm_ir/model.py`

Typed stack IR: Type/Signature/Reference, Operation, Handler, blocks/edges и экспорт.

[Исходник](../jcvm_ir/model.py) · [Руководство](modules/jcvm_ir.md)

Определения: `IRValidationError`; `Type` — `stack_kind()`, `slots()`; `Signature`; `Reference`; `Op`; `Operation`; `Handler`; `Edge`; `Block`; `MethodIR` — `to_json()`, `to_text()`.

### `jcvm_ir/resolver.py`

Nibble type descriptors, проверенные CP references и explicit interface signatures.

[Исходник](../jcvm_ir/resolver.py) · [Руководство](modules/jcvm_ir.md)

Определения: `DescriptorTypes` — `get()`, `signature()`; `ReferenceResolver` — `resolve()`, `class_type()`, `resolve_interface()`.

## jvm_like_ir

### `jvm_like_ir/__init__.py`

Публичные реэкспорты модели и builder.

[Исходник](../jvm_like_ir/__init__.py) · [Руководство](modules/jvm_like_ir.md)

Определений классов/функций верхнего уровня нет; назначение — реэкспорты/константы.

### `jvm_like_ir/__main__.py`

Standalone CAP→JVM-like CLI без опции interface signatures.

[Исходник](../jvm_like_ir/__main__.py) · [Руководство](modules/jvm_like_ir.md)

Определения: `main()`.

### `jvm_like_ir/builder.py`

Stack elimination без повторения эффектов; перенос stack values по рёбрам.

[Исходник](../jvm_like_ir/builder.py) · [Руководство](modules/jvm_like_ir.md)

Определения: `JVMLikeIRBuilder` — `build()`.

### `jvm_like_ir/model.py`

Stack-free typed model с block parameters, immutable temporaries и source offsets.

[Исходник](../jvm_like_ir/model.py) · [Руководство](modules/jvm_like_ir.md)

Определения: `LoweringError`; `ValueType` — `bits()`, `slots()`, `of()`; `Value`; `Constant`; `Argument`; `Statement`; `Terminator`; `Edge`; `Block`; `Method` — `to_json()`, `to_text()`, `validate()`.

### `jvm_like_ir/text.py`

Читаемый дамп operands, statements и method.

[Исходник](../jvm_like_ir/text.py) · [Руководство](modules/jvm_like_ir.md)

Определения: `operand()`; `reference()`; `format_statement()`; `format_method()`.

### `jvm_like_ir/validation.py`

Типы, definite assignment, двухслотовые locals, edges и ordered handlers.

[Исходник](../jvm_like_ir/validation.py) · [Руководство](modules/jvm_like_ir.md)

Определения: `require()`; `validate()`; `_statement_types()`; `_store()`; `_validate_locals()`.

## soot_ir

### `soot_ir/__init__.py`

Публичные реэкспорты builder, symbols, модели и ошибок.

[Исходник](../soot_ir/__init__.py) · [Руководство](modules/soot_ir.md)

Определений классов/функций верхнего уровня нет; назначение — реэкспорты/константы.

### `soot_ir/__main__.py`

JVM-like JSON→Soot JSON/Jimple CLI с защитой входных файлов.

[Исходник](../soot_ir/__main__.py) · [Руководство](modules/soot_ir.md)

Определения: `main()`.

### `soot_ir/builder.py`

Jimple-подобные Units, explicit narrowing, edge/exception bridges и source map.

[Исходник](../soot_ir/builder.py) · [Руководство](modules/soot_ir.md)

Определения: `SootIRBuilder` — `build()`, `build_program()`; `_MethodBuilder` — `error()`, `mark()`, `fresh()`, `fresh_mark()`, `local()`, `constant()`, `emit()`, `assign()`, `cast()`, `int_value()`, `narrow()`, `declared()`, `slot()`, `operand()`, `result()`, `finish_numeric()`, `check_arity()`, `lower_statement()`, `prepare_parameters()`, `prepare_edges()`, `normal_edges()`, `lower_terminator()`, `prologue()`, `collect_traps()`, `edge_bridges()`, `exception_bridges()`, `build()`; `backend_features()`; `make_blocks()`.

### `soot_ir/input.py`

Нормализация model/dict/JSON и имён операций на входе.

[Исходник](../soot_ir/input.py) · [Руководство](modules/soot_ir.md)

Определения: `LoweringError`; `plain()`; `read_method()`; `kind()`; `stack_kind()`; `op_name()`; `terminator_kind()`.

### `soot_ir/model.py`

Сериализуемые locals/expressions/Units/blocks/traps/methods/program.

[Исходник](../soot_ir/model.py) · [Руководство](modules/soot_ir.md)

Определения: `Local`; `Value`; `MethodRef` — `signature()`; `FieldRef` — `signature()`; `Expr`; `Unit`; `Block`; `Trap`; `Method` — `to_json()`, `to_text()`, `validate()`; `Program` — `to_json()`, `require_resolved_symbols()`.

### `soot_ir/reference_types.py`

Консервативный reference type inference; join конфликтов в Object.

[Исходник](../soot_ir/reference_types.py) · [Руководство](modules/soot_ir.md)

Определения: `infer_reference_types()`.

### `soot_ir/source_validation.py`

Проверка исходной JVM-like структуры до lowering.

[Исходник](../soot_ir/source_validation.py) · [Руководство](modules/soot_ir.md)

Определения: `validate_source()`.

### `soot_ir/symbols.py`

CAP keys, names, declared types и регистрация всех методов до тел.

[Исходник](../soot_ir/symbols.py) · [Руководство](modules/soot_ir.md)

Определения: `package_key()`; `reference_key()`; `SymbolTable` — `from_dict()`, `class_name()`, `reference_class()`, `type_name()`, `register()`, `method_ref()`, `field_ref()`, `catch_type()`.

### `soot_ir/text.py`

Текстовое представление Soot IR; не Java compiler.

[Исходник](../soot_ir/text.py) · [Руководство](modules/soot_ir.md)

Определения: `render()`; `method_text()`.

### `soot_ir/validation.py`

Проверка результата: locals/types/targets/traps и definite assignment.

[Исходник](../soot_ir/validation.py) · [Руководство](modules/soot_ir.md)

Определения: `validate()`.

## pysoot_adapter

### `pysoot_adapter/__init__.py`

Публичный фасад adapter, metadata, результата и ошибок.

[Исходник](../pysoot_adapter/__init__.py) · [Руководство](modules/pysoot_adapter.md)

Определений классов/функций верхнего уровня нет; назначение — реэкспорты/константы.

### `pysoot_adapter/backend.py`

Lazy import и проверка dataclass field contract выбранной ревизии pysoot.

[Исходник](../pysoot_adapter/backend.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `load_backend()`.

### `pysoot_adapter/builder.py`

Реальные pysoot objects, сверка bodies/declarations и разделение external dependencies.

[Исходник](../pysoot_adapter/builder.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `PySootAdapter` — `build()`; `_ProgramBuilder` — `error()`, `method_ref()`, `field_ref()`, `value()`, `statement()`, `convert_method()`, `build()`.

### `pysoot_adapter/cap_metadata.py`

Проверенный Class↔Descriptor join по offset и перевод CAP flags.

[Исходник](../pysoot_adapter/cap_metadata.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `_attrs()`; `metadata_from_cap()`.

### `pysoot_adapter/errors.py`

Ошибки adapter contract и dependency loading.

[Исходник](../pysoot_adapter/errors.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `AdapterError`; `DependencyError`.

### `pysoot_adapter/metadata.py`

Отдельные class/field/method/applet declarations, tokens и aliases.

[Исходник](../pysoot_adapter/metadata.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `FieldMetadata`; `MethodMetadata`; `ClassMetadata`; `AppletMetadata`; `ProgramMetadata`.

### `pysoot_adapter/model.py`

AdaptedProgram и CAP side metadata; диагностическая сериализация без importer.

[Исходник](../pysoot_adapter/model.py) · [Руководство](modules/pysoot_adapter.md)

Определения: `MethodDetails`; `_node()`; `AdaptedProgram` — `required_backend_features()`, `require_resolved_symbols()`, `require_backend_features()`, `method_to_dict()`, `to_dict()`, `to_json()`, `method_to_text()`, `export()`.

### `pysoot_adapter/tests/test_adapter.py`

19 unit/integration регрессий adapter и synthetic numeric helpers.

[Исходник](../pysoot_adapter/tests/test_adapter.py) · [Руководство](modules/testing_examples.md)

Определения: `local()`; `constant()`; `body()`; `declarations()`; `adapt()`; `run_numeric()`; `AdapterTests` — `test_real_nodes_branch_targets_are_unit_labels_not_block_indices()`, `test_short_wraparound_preserved_by_cast_sequence()`, `test_switch_shared_targets_and_default()`, `test_constructor_calls_and_definition_are_renamed_together()`, `test_internal_virtual_alias_resolves_to_declared_method()`, `test_fields_use_name_then_owner_and_reuse_receiver_local()`, `test_exception_edges_order_and_traps_are_not_declared_throws()`, `test_external_calls_remain_explicit_obligations()`, `test_bad_parameter_and_unknown_schema_rejected()`, `test_missing_class_or_method_metadata_fails()`, `test_static_field_null_unary_and_array_nodes()`, `test_abstract_interface_and_interface_call()`, `test_throw_is_preserved_with_backend_requirement()`, `test_backend_import_does_not_start_jvm()`; `CAPIntegrationTests` — `setUpClass()`, `test_all_nine_methods_preserve_instructions_edges_and_offsets()`, `test_constructor_access_flags_and_field_declarations()`, `test_metadata_requires_offsets_and_matching_imports()`, `test_class_offsets_are_info_relative_and_join_is_not_positional()`, `test_diagnostics_export_is_deterministic_and_has_source_mapping()`.

## angr_integration

### `angr_integration/__init__.py`

Публичный фасад loader, symbolic argument и ошибок.

[Исходник](../angr_integration/__init__.py) · [Руководство](modules/angr_integration.md)

Определений классов/функций верхнего уровня нет; назначение — реэкспорты/константы.

### `angr_integration/backend.py`

CLE Soot backend для готовых объектов, без Lifter и native memory.

[Исходник](../angr_integration/backend.py) · [Руководство](modules/angr_integration.md)

Определения: `CAPSootBackend`.

### `angr_integration/calls.py`

CallTarget и проверенный static/special/virtual/interface dispatch.

[Исходник](../angr_integration/calls.py) · [Руководство](modules/angr_integration.md)

Определения: `CallTarget`; `invocation_mode()`; `CallResolver` — `resolve()`, `potential_targets()`.

### `angr_integration/demo.py`

Синтетический sign(short) с двумя путями для проверки loader/engine.

[Исходник](../angr_integration/demo.py) · [Руководство](modules/angr_integration.md)

Определения: `signed()`; `build_example()`; `run_demo()`; `main()`.

### `angr_integration/dependencies.py`

Strict version checks angr/CLE/archinfo и lazy dependencies.

[Исходник](../angr_integration/dependencies.py) · [Руководство](modules/angr_integration.md)

Определения: `load_dependencies()`.

### `angr_integration/errors.py`

Loader/dependency/readiness и heap errors с optional fault condition.

[Исходник](../angr_integration/errors.py) · [Руководство](modules/angr_integration.md)

Определения: `LoaderError`; `DependencyError`; `ExecutionNotReady`; `HeapError`.

### `angr_integration/heap.py`

Path-local heap; immutable arrays, guarded accesses, copy и transaction snapshots.

[Исходник](../angr_integration/heap.py) · [Руководство](modules/angr_integration.md)

Определения: `HeapReference`; `_Array`; `CAPHeap` — `copy()`, `merge()`, `widen()`, `default()`, `validate_reference()`, `normalize()`, `new_object()`, `read_field()`, `write_field()`, `new_array()`, `array_length()`, `read_array()`, `write_array()`, `read_slice()`, `write_slice()`, `transaction_snapshot()`, `restore_transaction()`, `cast_reference()`.

### `angr_integration/heap_types.py`

Class declarations, lineage, field layout и assignability.

[Исходник](../angr_integration/heap_types.py) · [Руководство](modules/angr_integration.md)

Определения: `is_reference_type()`; `is_value_type()`; `HeapSchema` — `lineage()`, `allocation_fields()`, `field()`, `assignable()`.

### `angr_integration/index.py`

Согласование CAP keys/offsets, Unit labels и Soot block/statement адресов.

[Исходник](../angr_integration/index.py) · [Руководство](modules/angr_integration.md)

Определения: `SourceLocation` — `to_dict()`; `MethodIndex` — `method()`, `key_for_descriptor()`, `entry()`, `address()`, `at_label()`, `at_offset()`, `source()`.

### `angr_integration/javacard_api.py`

17 explicit name1 API models, copyable JavaCardState, concrete DES.

[Исходник](../angr_integration/javacard_api.py) · [Руководство](modules/javacard_runtime.md)

Определения: `ISOExit`; `APIModel`; `DESKeyState`; `CipherState`; `JavaCardState` — `copy()`, `merge()`, `widen()`, `event()`, `begin()`, `commit()`, `abort()`, `deselect()`; `integer()`; `byte_values()`; `des_crypt()`; `Name1API` — `lookup()`, `accepts_receiver()`, `invoke()`.

### `angr_integration/javacard_session.py`

Install/APDU lifecycle, fresh frames, завершённые/ошибочные/активные пути.

[Исходник](../angr_integration/javacard_session.py) · [Руководство](modules/javacard_runtime.md)

Определения: `CommandFault`; `CommandRun` — `summary()`; `JavaCardSession` — `run()`, `install()`, `prepare_command()`, `transmit()`, `choose()`.

### `angr_integration/loader.py`

LoadedProgram, entry/profile selection, адреса и load reports.

[Исходник](../angr_integration/loader.py) · [Руководство](modules/angr_integration.md)

Определения: `LoadedProgram` — `method_address()`, `address_for_label()`, `addresses_for_offset()`, `source_location()`, `create_call_state()`, `create_heap_state()`, `to_dict()`, `export()`; `AngrLoader` — `load()`.

### `angr_integration/memory_demo.py`

Синтетический instance method с field/array и проверкой fork isolation.

[Исходник](../angr_integration/memory_demo.py) · [Руководство](modules/angr_integration.md)

Определения: `build_example()`; `signed()`; `run_demo()`; `main()`.

### `angr_integration/name1_demo.py`

Настоящий CAP: install, 15 APDU, три symbolic P1 branches и expected null fault.

[Исходник](../angr_integration/name1_demo.py) · [Руководство](modules/javacard_runtime.md)

Определения: `load_name1()`; `run_demo()`; `main()`.

### `angr_integration/readiness.py`

Preflight операций и транзитивно достижимых методов/возможных virtual целей.

[Исходник](../angr_integration/readiness.py) · [Руководство](modules/angr_integration.md)

Определения: `ExecutionIssue` — `to_dict()`; `walk()`; `ExecutionReadiness` — `reachable()`, `issues()`, `require()`.

### `angr_integration/runtime.py`

CAPSimOS frames и checked Soot engine, API exits и CAPMemoryError.

[Исходник](../angr_integration/runtime.py) · [Руководство](modules/angr_integration.md)

Определения: `CAPSimOS` — `state_blank()`; `CAPMemoryError`; `CheckedSootEngine` — `process_successors()`, `get_unconstrained_simprocedure()`.

### `angr_integration/semantics.py`

Project-local translators heap/casts/calls/reference equality и signed remainder.

[Исходник](../angr_integration/semantics.py) · [Руководство](modules/angr_integration.md)

Определения: `CAPInvoke`; `evaluate()`; `CAPAssign`; `translate_stmt()`.

### `angr_integration/state.py`

Типизированные concrete/symbolic arguments, receiver/base_state и return terminator.

[Исходник](../angr_integration/state.py) · [Руководство](modules/angr_integration.md)

Определения: `SymbolicArgument`; `encode_argument()`; `create_call_state()`.

### `angr_integration/tests/test_calls.py`

6 virtual/special/null/remainder tests и генератор call programs.

[Исходник](../angr_integration/tests/test_calls.py) · [Руководство](modules/testing_examples.md)

Определения: `make_method()`; `call_program()`; `CallTests` — `test_virtual_uses_cap_token_despite_different_synthetic_names()`, `test_special_retains_declared_super_target_and_constructor_field()`, `test_null_instance_receiver_fault_is_not_an_unconstrained_return()`; `RemainderTests` — `setUpClass()`, `test_signed_java_remainder_and_minimum_overflow_case()`, `test_symbolic_divisor_never_silently_drops_possible_zero()`, `test_symbolic_dividend_preserved_for_all_signed_inputs()`.

### `angr_integration/tests/test_heap.py`

16 heap/reference/state-copy regressions и fixture helpers.

[Исходник](../angr_integration/tests/test_heap.py) · [Руководство](modules/testing_examples.md)

Определения: `local()`; `const()`; `unit()`; `field()`; `array()`; `method()`; `load()`; `value_field()`; `array_method()`; `HeapTests` — `run_ok()`, `run_fault()`, `test_symbolic_paths_modify_fields_and_arrays_independently()`, `test_new_object_default_fields_alias_and_narrow_storage()`, `test_receiver_and_inherited_fields_are_typed_and_base_is_unchanged()`, `test_all_primitive_arrays_defaults_length_and_storage_width()`, `test_symbolic_primitive_array_read_preserves_all_valid_indices()`, `test_symbolic_write_is_conditional_and_does_not_modify_base_state()`, `test_out_of_bounds_and_possible_fault_are_not_pruned()`, `test_null_field_array_and_length_faults_have_source_locations()`, `test_allocation_length_is_never_clamped_or_arbitrarily_concretized()`, `test_references_are_returned_and_alias_through_static_calls()`, `test_reference_equality_distinguishes_alias_fresh_object_and_null()`, `test_reference_cast_preserves_dynamic_type_and_checks_mismatch()`, `test_foreign_or_forged_references_are_rejected()`, `test_reference_array_defaults_covariance_and_bad_store()`, `test_symbolic_reference_array_index_and_state_merge_fail_explicitly()`, `test_external_hierarchy_and_static_fields_are_not_fabricated()`.

### `angr_integration/tests/test_javacard.py`

20 lifecycle/APDU/transaction/crypto/model-identity regressions.

[Исходник](../angr_integration/tests/test_javacard.py) · [Руководство](modules/testing_examples.md)

Определения: `JavaCardTests` — `setUpClass()`, `setUp()`, `field()`, `send()`, `test_install_executes_constructor_and_registers_original_applet()`, `test_commands_after_iso_exception_enter_fresh_java_frames()`, `test_ecb_known_answer_and_cbc_match_independent_cipher_api()`, `test_status_words_and_partial_receive_preserve_key()`, `test_real_null_key_fault_has_exact_cap_location()`, `test_symbolic_p1_explores_all_values_and_isolates_persistent_writes()`, `test_symbolic_crypto_data_is_rejected_unless_uniquely_constrained()`, `test_transaction_rollback_excludes_transient_buffer_and_key_data()`, `test_transaction_snapshots_are_independent_and_commit_persists()`, `test_unfinished_transaction_aborts_at_command_boundary()`, `test_transaction_allocation_nesting_and_invalid_commit_fail_explicitly()`, `test_normal_return_with_open_transaction_is_not_success()`, `test_api_arraycopy_overlap_and_failure_atomicity()`, `test_global_apdu_references_cannot_escape_to_persistent_fields()`, `test_api_binding_identity_and_unsupported_algorithms_are_checked()`, `test_unmodeled_interface_implementation_requires_cap_token_map()`, `test_dofinal_iv_reset_deselect_and_key_change_guard()`, `test_step_budget_never_reports_success_or_updates_card_state()`, `test_single_two_three_key_des_and_degenerate_key()`, `test_deliverable_demo_checks_every_expected_outcome()`.

### `angr_integration/tests/test_loader.py`

18 loader/addressing/primitive execution regressions и builders fixtures.

[Исходник](../angr_integration/tests/test_loader.py) · [Руководство](modules/testing_examples.md)

Определения: `local()`; `const()`; `body()`; `adapt()`; `branch_method()`; `signed32()`; `LoaderTests` — `execute()`, `returns()`, `test_real_loader_no_lifter_jvm_or_implicit_library_bodies()`, `test_source_address_roundtrip_distinguishes_labels_blocks_and_offsets()`, `test_symbolic_signed_branch_forks_and_solves_real_constraints()`, `test_primitive_widths_and_sign_extension()`, `test_short_wraparound_casts_are_executed_by_angr()`, `test_internal_static_call_transfers_args_and_returns_to_caller()`, `test_switch_shared_targets_negative_case_and_default()`, `test_loop_step_budget_keeps_active_state()`, `test_external_call_loaded_but_never_given_an_unconstrained_return()`, `test_unknown_direct_address_cannot_use_stock_unconstrained_fallback()`, `test_unsupported_callee_is_rejected_transitively()`, `test_unsupported_operand_shapes_do_not_claim_execution_readiness()`, `test_exception_metadata_survives_loading_and_blocks_execution()`, `test_bad_arguments_and_entry_keys_are_explicit_errors()`, `test_multiple_methods_do_not_choose_an_arbitrary_entry()`, `test_receiver_is_explicit_and_base_state_is_copied()`, `test_interpreter_errors_are_recorded_not_skipped()`, `test_actual_cap_pipeline_loads_all_methods_and_exports_source_map()`.

## integration_tests

### `integration_tests/test_name1.py`

14 end-to-end и binary boundary regressions, оригинальные CAP/JCA fixtures.

[Исходник](../integration_tests/test_name1.py) · [Руководство](modules/testing_examples.md)

Определения: `component()`; `Name1Tests` — `setUpClass()`, `test_cap22_components_and_real_aids()`, `test_decoded_instruction_sequences_match_compiler_jca()`, `test_pysoot_retains_interface_call_and_cap_offsets()`, `test_angr_load_does_not_claim_applet_is_executable()`, `test_uninitialized_two_key_field_is_preserved()`, `test_missing_or_wrong_interface_binding_is_rejected()`, `test_interface_word_count_and_binding_validation()`, `test_cap21_pipeline_regression()`; `BinaryBoundaryTests` — `test_operand_widths_and_unsigned_indices()`, `test_truncated_fixed_width_instructions_rejected()`, `test_array_checkcast_and_invalid_atype()`, `test_header_name_boundary_and_size_validation()`, `test_directory_counts_for_both_formats_and_custom_component()`, `test_class_signature_pool_boundary()`.
