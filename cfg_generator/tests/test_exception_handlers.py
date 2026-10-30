"""D-04: method-local handler regions must survive CFG construction."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest

from cap_decompile.components.method_component import ExceptionHandlerInfo
from cap_decompile.model.method_info import OPCODES, parse_bytecode
from cfg_generator.analysis.block_splitter import split_basic_blocks
from cfg_generator.analysis.exception_edges import build_exception_edges
from cfg_generator.builder import build_cfg
from cfg_generator.model.edge import EdgeType
from jcvm_ir import Handler, MethodInput, Signature, VOID


CODES = {spec[0]: code for code, spec in OPCODES.items()}


def method_with(handlers=(), body=None):
    if body is None:
        body = bytes(CODES[name] for name in (
            "nop", "aconst_null", "arraylength", "pop", "return", "pop", "return",
        ))
    return MethodInput(
        "0102030405/class_0/method_0", 0, 0, body, parse_bytecode(body),
        1, 0, 0, handlers, Signature((), VOID), True,
    )


def exceptional_offsets(cfg):
    starts = {block.id: block.start_offset for block in cfg.blocks}
    return [(starts[edge.source], starts[edge.target]) for edge in cfg.edges
            if edge.edge_type == EdgeType.EXCEPTION]


class ExceptionHandlerTests(unittest.TestCase):
    def test_typed_handler_splits_both_region_boundaries_and_target(self):
        cfg = build_cfg(method_with((Handler(1, 4, 5, 0),)))
        self.assertEqual([block.start_offset for block in cfg.blocks], [0, 1, 4, 5])
        self.assertEqual(exceptional_offsets(cfg), [(1, 5)])
        self.assertEqual([block.start_offset for block in cfg.blocks
                          if block.is_exception_handler], [5])
        source, target = cfg.blocks[1], cfg.blocks[3]
        self.assertIn(target.id, source.successors)
        self.assertIn(source.id, target.predecessors)
        # end is exclusive: the return at offset 4 is outside the region.
        self.assertEqual(cfg.blocks[2].successors, [])

    def test_exclusive_end_may_equal_bytecode_length(self):
        method = method_with((Handler(1, 7, 5, 0),))
        cfg = build_cfg(method)
        self.assertEqual([block.start_offset for block in cfg.blocks], [0, 1, 5])
        self.assertEqual(exceptional_offsets(cfg), [(1, 5), (5, 5)])
        self.assertNotIn(len(method.bytecodes), cfg.offset_to_block)

    def test_nested_regions_and_shared_targets_keep_table_order_and_duplicates(self):
        body = method_with().bytecodes + bytes([CODES["pop"], CODES["return"]])
        method = method_with((
            Handler(1, 4, 7, 3), Handler(2, 4, 5, 0, True), Handler(1, 4, 7, 0),
        ), body)
        cfg = build_cfg(method)
        self.assertEqual(exceptional_offsets(cfg), [
            (1, 7), (2, 7), (2, 5), (1, 7), (2, 7),
        ])
        self.assertEqual(cfg.blocks[cfg.offset_to_block[7]].predecessors, [1, 2, 1, 2])

    def test_explicit_legacy_mapping_is_still_supported_at_cfg_boundary(self):
        typed = build_cfg(method_with((Handler(1, 4, 5, 0),)))
        legacy = build_cfg(method_with(({"start_pc": 1, "end_pc": 4, "handler_pc": 5},)))
        self.assertEqual(legacy, typed)

    def test_empty_or_absent_table_leaves_normal_cfg_unchanged(self):
        baseline = build_cfg(method_with())
        for handlers in ((), [], None):
            with self.subTest(handlers=handlers):
                self.assertEqual(build_cfg(method_with(handlers)), baseline)
        without_table = SimpleNamespace(token=0, instructions=method_with().instructions)
        self.assertEqual(build_cfg(without_table), baseline)

    def test_invalid_ranges_and_instruction_boundaries_are_rejected(self):
        # bspush has an operand byte at offset 2; it is not an instruction boundary.
        body = bytes([CODES["nop"], CODES["bspush"], 7, CODES["pop"],
                      CODES["return"], CODES["pop"], CODES["return"]])
        cases = (
            Handler(2, 4, 5, 0), Handler(1, 2, 5, 0), Handler(1, 4, 2, 0),
            Handler(-1, 4, 5, 0), Handler(1, 8, 5, 0), Handler(1, 4, 7, 0),
            Handler(1, 4, -1, 0), Handler(4, 1, 5, 0), Handler(1, 1, 5, 0),
        )
        for handler in cases:
            with self.subTest(handler=handler):
                with self.assertRaisesRegex(ValueError, "Exception handler 0"):
                    build_cfg(method_with((handler,), body))

    def test_coordinates_must_be_integers_not_bools_or_coerced_values(self):
        for field in ("start", "end", "target"):
            for value in (True, "1", 1.0, None):
                with self.subTest(field=field, value=value):
                    handler = replace(Handler(1, 4, 5, 0), **{field: value})
                    with self.assertRaisesRegex(ValueError, "Exception handler 0"):
                        build_cfg(method_with((handler,)))

    def test_raw_cap_coordinates_are_not_guessed(self):
        raw = ExceptionHandlerInfo(12, 0, 3, 16, 0)
        with self.assertRaisesRegex(ValueError, "method-local"):
            build_cfg(method_with((raw,)))

    def test_incomplete_legacy_mapping_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Exception handler 0"):
            build_cfg(method_with(({"start_pc": 1, "end_pc": 4},)))

    def test_nonempty_table_requires_bytecode_length(self):
        method = method_with((Handler(1, 4, 5, 0),))
        del method.bytecodes
        with self.assertRaisesRegex(ValueError, "bytecodes"):
            build_cfg(method)

    def test_handler_in_empty_method_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Exception handler 0"):
            build_cfg(method_with((Handler(0, 1, 0, 0),), b""))

    def test_direct_edge_builder_rejects_unsplit_start_end_or_target(self):
        for handler, leaders, field in (
            (Handler(1, 4, 5, 0), [0, 4, 5], "start"),
            (Handler(1, 4, 5, 0), [0, 1, 5], "end"),
            (Handler(1, 4, 2, 0), [0, 1, 4, 5], "target"),
        ):
            with self.subTest(field=field):
                method = method_with((handler,))
                blocks = split_basic_blocks(method.instructions, leaders)
                before = deepcopy(blocks)
                with self.assertRaisesRegex(ValueError, f"{field}.*block"):
                    build_exception_edges(blocks, method)
                self.assertEqual(blocks, before)

    def test_invalid_later_handler_does_not_partially_mutate_blocks(self):
        for later in (Handler(1, 4, 99, 0), Handler(1, 4, 2, 0)):
            with self.subTest(later=later):
                method = method_with((Handler(1, 4, 5, 0), later))
                blocks = split_basic_blocks(method.instructions, [0, 1, 4, 5])
                before = deepcopy(blocks)
                with self.assertRaisesRegex(ValueError, "Exception handler 1"):
                    build_exception_edges(blocks, method)
                self.assertEqual(blocks, before)

    def test_build_does_not_rewrite_source_handler_metadata_or_instructions(self):
        method = method_with((Handler(1, 4, 5, 3, True),))
        before = deepcopy(method)
        build_cfg(method)
        self.assertEqual(method, before)


if __name__ == "__main__":
    unittest.main()
