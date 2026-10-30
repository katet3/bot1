"""D-04: CAP handler coordinates and ordered traps across the IR pipeline."""
from types import SimpleNamespace
import unittest

from cap_decompile.components.method_component import (
    ExceptionHandlerInfo, MethodHeaderInfo, MethodInfo,
)
from cap_decompile.model.method_info import OPCODES, parse_bytecode
from cfg_generator.builder import build_cfg
from jcvm_ir import Handler, IRBuilder, MethodInput, Signature, VOID
from jvm_like_ir import JVMLikeIRBuilder
from main import (
    build_cfgs, build_jcvm_ir, build_jvm_like_ir, build_soot_ir,
    extract_methods, verify_methods,
)
from soot_ir import SootIRBuilder, SymbolTable
from verification_engine.verifier import Verifier


CODES = {spec[0]: code for code, spec in OPCODES.items()}


def division_method(handlers):
    body = bytes(CODES[name] for name in (
        "nop", "sconst_1", "sconst_0", "sdiv", "pop", "return",
        "pop", "return", "pop", "return",
    ))
    return MethodInput(
        "0102030405/class_0/method_0", 0, 0, body, parse_bytecode(body),
        2, 0, 0, handlers, Signature((), VOID), True,
    )


def symbols():
    return SymbolTable.from_dict({
        "package_aid": "0102030405", "package_version": [1, 0],
        "catch_types": {"3": "java.lang.ArithmeticException"},
    })


class HandlerPipelineTests(unittest.TestCase):
    def test_nested_handlers_preserve_priority_types_stop_bit_and_caught_stack(self):
        method = division_method((Handler(1, 5, 8, 3), Handler(2, 5, 6, 0, True)))
        cfg = build_cfg(method)
        report = Verifier().verify(method)
        self.assertTrue(report.success, report.to_text())
        ir = IRBuilder().build(method, cfg=cfg)
        # The independent JCVM builder must agree with the supplied CFG.
        self.assertEqual(ir, IRBuilder().build(method))
        self.assertEqual(ir.handlers, method.exception_handlers)
        caught = [block for block in ir.blocks if block.start in (6, 8)]
        self.assertEqual([block.input_stack for block in caught], [("reference",)] * 2)
        jvm = JVMLikeIRBuilder().build(ir)
        soot = SootIRBuilder(symbols()).build(jvm)
        self.assertEqual([(trap.priority, trap.exception_type, trap.stop_bit)
                          for trap in soot.traps], [
            (0, "java.lang.ArithmeticException", False),
            (1, "java.lang.Throwable", True),
        ])
        units = {unit.label: unit for unit in soot.units}
        for trap in soot.traps:
            self.assertEqual(units[trap.begin].offset, 3)
            self.assertEqual(units[trap.begin].handlers, (0, 1))
            self.assertEqual(units[trap.handler].kind, "identity")
            self.assertEqual(units[trap.handler].right.kind, "caught_exception")

    def test_shared_handler_target_keeps_both_ordered_traps(self):
        method = division_method((Handler(1, 5, 6, 3), Handler(1, 5, 6, 0, True)))
        # Remove the unused second catch block so all blocks remain reachable.
        method.bytecodes = method.bytecodes[:8]
        method.instructions = parse_bytecode(method.bytecodes)
        ir = IRBuilder().build(method, cfg=build_cfg(method))
        soot = SootIRBuilder(symbols()).build(JVMLikeIRBuilder().build(ir))
        self.assertEqual([trap.priority for trap in soot.traps], [0, 1])
        self.assertEqual(ir.handlers, method.exception_handlers)

    def test_cap_metadata_adapter_to_soot_uses_method_local_offsets(self):
        # Component-relative offsets deliberately differ from method-local ones.
        # This is a metadata fixture, not a binary CAP parser or runtime test.
        body = division_method(()).bytecodes[:8]
        raw_handler = ExceptionHandlerInfo(12, 1, 4, 17, 0)
        linked_method = MethodInfo(0, MethodHeaderInfo(0, 2, 0, 0), body, [raw_handler])
        descriptor = SimpleNamespace(
            method_offset=9, token=0, access_flags=0x08, type_offset=2,
            bytecode_count=len(body), exception_handler_index=0, exception_handler_count=1,
        )
        cap = SimpleNamespace(
            header=SimpleNamespace(package=SimpleNamespace(
                aid=bytes.fromhex("0102030405"), major_version=1, minor_version=0,
            )),
            constant_pool=SimpleNamespace(constant_pool=[]),
            method_component=SimpleNamespace(
                handler_count=1, exception_handlers=[raw_handler], methods=[linked_method],
            ),
            descriptor=SimpleNamespace(
                types=SimpleNamespace(raw_types=b"\x01\x10", constant_pool_count=0,
                                      constant_pool_types=[]),
                classes=[SimpleNamespace(this_class_ref=0, methods=[descriptor])],
            ),
        )
        methods = extract_methods(cap)
        self.assertEqual(methods[0].exception_handlers, (Handler(1, 5, 6, 0, True),))
        cfgs = build_cfgs(methods)
        verify_methods(methods)
        ir = build_jcvm_ir(cap, methods, cfgs)
        program = build_soot_ir(build_jvm_like_ir(ir), symbols())
        self.assertEqual(len(program.methods), 1)
        self.assertEqual([(t.priority, t.exception_type, t.stop_bit)
                          for t in program.methods[0].traps], [(0, "java.lang.Throwable", True)])
        self.assertEqual((raw_handler.start_offset, raw_handler.handler_offset), (12, 17))


if __name__ == "__main__":
    unittest.main()
