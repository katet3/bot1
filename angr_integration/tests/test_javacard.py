"""Execute the real applet, plus model boundaries and state isolation."""
from dataclasses import replace
import tempfile
import unittest

from angr import claripy
from archinfo.arch_soot import SootNullConstant
from Crypto.Cipher import DES3

from angr_integration.errors import HeapError
from angr_integration.javacard_api import byte_values, des_crypt, integer
from angr_integration.javacard_session import JavaCardSession
from angr_integration.name1_demo import load_name1, run_demo, KEY, PLAIN, ECB, IV


class JavaCardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loaded = load_name1()

    def setUp(self):
        self.session = JavaCardSession(self.loaded)
        self.session.install()

    def field(self, state, name, ty):
        ref = state.javacard.registrations[self.session.aid]
        return state.cap_heap.read_field(ref, ref.type, name, ty)

    def send(self, *args, sw=0x9000, **kwargs):
        run = self.session.transmit(*args, **kwargs)
        self.assertEqual(run.errored, (), run.summary())
        self.assertEqual(run.active, ())
        self.assertEqual(len(run.completed), 1)
        state = run.completed[0]
        self.assertEqual(integer(state, state.javacard.status, 'sw', signed=False), sw)
        return state

    def test_install_executes_constructor_and_registers_original_applet(self):
        state = self.session.state
        self.assertEqual(tuple(state.javacard.registrations), (bytes.fromhex('11223344556600'),))
        self.assertTrue(state.javacard.deletion_requested)
        self.assertFalse(state.javacard.installing)
        self.assertIsInstance(self.field(state, 'tempDesKey2', 'javacard.security.Key'), SootNullConstant)
        self.assertEqual(state.solver.eval(self.field(state, 'desKeyLen', 'byte')), 0)
        self.assertEqual(state.solver.eval(state.cap_heap.array_length(self.field(state, 'desKey', 'byte[]'))), 32)
        self.assertEqual(sorted(c.algorithm for c in state.javacard.ciphers.values()), [1, 5])
        self.assertEqual([k.bits for k in state.javacard.keys.values()], [192])
        self.assertTrue(all(k.data is None for k in state.javacard.keys.values()))

    def test_commands_after_iso_exception_enter_fresh_java_frames(self):
        self.send(0xa4, selecting=True)
        self.send(0x7f, sw=0x6d00)
        self.send(0x22, data=bytes(8), sw=0x6985)
        self.send(0x20, 2, data=KEY)
        state = self.send(0x22, data=PLAIN)
        self.assertEqual(byte_values(state, state.javacard.response, 'out'), ECB)
        self.assertIsNone(state.javacard.exception)

    def test_ecb_known_answer_and_cbc_match_independent_cipher_api(self):
        self.send(0x20, 2, data=KEY)
        self.send(0x21, data=IV)
        for p2, expected in ((0, ECB), (1, DES3.new(KEY, DES3.MODE_CBC, iv=IV).encrypt(PLAIN))):
            with self.subTest(p2=p2):
                state = self.send(0x22, 0, p2, PLAIN)
                self.assertEqual(byte_values(state, state.javacard.response, 'out'), expected)
                state = self.send(0x22, 1, p2, expected)
                self.assertEqual(byte_values(state, state.javacard.response, 'out'), PLAIN)
        # Crypto writes at APDU offset 0 while input starts at 5; overlap is safe.

    def test_status_words_and_partial_receive_preserve_key(self):
        for args, kwargs, sw in (
            ((0x20, 3), {'data': KEY}, 0x6a86),
            ((0x20, 2), {'data': KEY[:16]}, 0x6700),
            ((0x21,), {'data': IV[:7]}, 0x6700),
            ((0x22,), {'data': PLAIN[:7]}, 0x6700),
            ((0x20, 2), {'data': KEY, 'receive_length': 8}, 0x6700),
        ):
            with self.subTest(args=args, kwargs=kwargs):
                end = self.send(*args, **kwargs, sw=sw)
                self.assertEqual(end.solver.eval(self.field(end, 'desKeyLen', 'byte')), 0)
                self.assertEqual(byte_values(end, end.cap_heap.read_slice(self.field(end, 'desKey', 'byte[]'), 0, 32), 'key'), bytes(32))
        # Buffer is shared across calls within one command, but cleared on the next.
        prepared = self.session.prepare_command(0x7f)
        self.assertEqual(byte_values(prepared, prepared.cap_heap.read_slice(prepared.javacard.buffer, 5, 255), 'tail'), bytes(255))

    def test_real_null_key_fault_has_exact_cap_location(self):
        self.send(0x20, 1, data=KEY[:16])
        previous = self.session.state
        run = self.session.transmit(0x22, data=PLAIN[:8])
        self.assertEqual((len(run.completed), len(run.active), len(run.errored)), (0, 0, 1))
        error = run.errored[0].error
        self.assertEqual(error.code, 'null_reference')
        self.assertEqual((error.source.method_key, error.source.cap_offset),
                         ('112233445566@1.0:internal:t6:o256', 41))
        self.assertIs(self.session.state, previous)  # No arbitrary faulty path becomes the card state.

    def test_symbolic_p1_explores_all_values_and_isolates_persistent_writes(self):
        p1 = claripy.BVS('test_key_p1', 8, explicit_name=True)
        previous = self.session.state
        run = self.session.transmit(0x20, p1, data=KEY)
        self.assertEqual((len(run.completed), len(run.active), len(run.errored)), (3, 0, 0))
        self.assertIs(self.session.state, previous)
        by_status = {integer(s, s.javacard.status, 'SW', signed=False): s for s in run.completed}
        self.assertEqual(set(by_status), {0x9000, 0x6700, 0x6a86})
        for sw, condition in ((0x9000, p1 == 2), (0x6700, p1 == 1), (0x6a86, (p1 != 1) & (p1 != 2))):
            state = by_status[sw]
            self.assertFalse(state.solver.satisfiable(extra_constraints=[~condition]))
            self.assertFalse(previous.solver.satisfiable(extra_constraints=[condition, ~claripy.And(*state.solver.constraints)]))
            self.assertEqual(state.solver.eval(self.field(state, 'desKeyLen', 'byte')), 24 if sw == 0x9000 else 0)
        self.assertEqual(previous.solver.eval(self.field(previous, 'desKeyLen', 'byte')), 0)

    def test_symbolic_crypto_data_is_rejected_unless_uniquely_constrained(self):
        self.send(0x20, 2, data=KEY)
        x = claripy.BVS('plaintext_byte', 8, explicit_name=True)
        payload = (x, *PLAIN[1:])
        run = self.session.transmit(0x22, data=payload)
        self.assertFalse(run.completed)
        self.assertEqual(len(run.errored), 1)
        self.assertEqual(run.errored[0].error.code, 'symbolic_api_argument')
        state = self.session.prepare_command(0x22, data=payload)
        state.solver.add(x == PLAIN[0])
        run = self.session.run(state)
        self.assertFalse(run.errored)
        self.assertEqual(len(run.completed), 1)
        end = run.completed[0]
        self.assertEqual(byte_values(end, end.javacard.response, 'out'), ECB)

    def test_transaction_rollback_excludes_transient_buffer_and_key_data(self):
        state = self.session.prepare_command(0x7f)
        heap, card = state.cap_heap, state.javacard
        receiver = card.registrations[self.session.aid]
        array = self.field(state, 'desKey', 'byte[]')
        key = self.field(state, 'tempDesKey3', 'javacard.security.Key')
        card.begin()
        heap.write_slice(array, 0, KEY)
        heap.write_field(receiver, receiver.type, 'desKeyLen', 'byte', 24)
        heap.write_slice(card.buffer, 5, b'X')
        self.loaded.readiness.api._set_key(state, key, array, 0)
        card.abort()
        self.assertEqual(byte_values(state, heap.read_slice(array, 0, 32), 'key'), bytes(32))
        self.assertEqual(state.solver.eval(self.field(state, 'desKeyLen', 'byte')), 0)
        self.assertEqual(byte_values(state, heap.read_slice(card.buffer, 5, 1), 'buffer'), b'X')
        self.assertEqual(byte_values(state, card.keys[key.allocation_id].data, 'transient key'), KEY)

    def test_transaction_snapshots_are_independent_and_commit_persists(self):
        base = self.session.prepare_command(0x7f)
        base.javacard.begin()
        left, right = base.copy(), base.copy()
        for state, byte in ((left, 7), (right, 9)):
            state.cap_heap.write_slice(self.field(state, 'desKey', 'byte[]'), 0, [byte])
        left.javacard.abort()
        right.javacard.commit()
        for state, expected in ((base, 0), (left, 0), (right, 9)):
            self.assertEqual(state.solver.eval(state.cap_heap.read_array(self.field(state, 'desKey', 'byte[]'), 0)), expected)
        self.assertIsNotNone(base.javacard.transaction)

    def test_unfinished_transaction_aborts_at_command_boundary(self):
        state = self.session.prepare_command(0x7f)
        state.javacard.begin()
        state.cap_heap.write_slice(self.field(state, 'desKey', 'byte[]'), 0, [17])
        run = self.session.run(state)
        self.assertFalse(run.errored)
        end = run.completed[0]
        self.assertEqual(integer(end, end.javacard.status, 'SW', signed=False), 0x6d00)
        self.assertIsNone(end.javacard.transaction)
        self.assertEqual(end.solver.eval(end.cap_heap.read_array(self.field(end, 'desKey', 'byte[]'), 0)), 0)

    def test_transaction_allocation_nesting_and_invalid_commit_fail_explicitly(self):
        state = self.session.state.copy()
        with self.assertRaisesRegex(HeapError, 'transaction_not_in_progress'):
            state.javacard.commit()
        state.javacard.begin()
        with self.assertRaisesRegex(HeapError, 'transaction_in_progress'):
            state.javacard.begin()
        with self.assertRaisesRegex(HeapError, 'transaction_allocation'):
            state.cap_heap.new_array('byte', 8)

    def test_normal_return_with_open_transaction_is_not_success(self):
        state = self.session.prepare_command(0xa4, selecting=True)
        state.javacard.begin()
        state.cap_heap.write_slice(self.field(state, 'desKey', 'byte[]'), 0, [17])
        run = self.session.run(state)
        self.assertFalse(run.completed)
        self.assertEqual(len(run.errored), 1)
        self.assertEqual(run.errored[0].error.code, 'uncommitted_transaction')
        end = run.errored[0].state
        self.assertIsNone(end.javacard.status)
        self.assertIsNone(end.javacard.transaction)
        self.assertEqual(end.solver.eval(end.cap_heap.read_array(self.field(end, 'desKey', 'byte[]'), 0)), 0)

    def test_api_arraycopy_overlap_and_failure_atomicity(self):
        state = self.session.state.copy()
        array = state.cap_heap.new_array('byte', 8)
        state.cap_heap.write_slice(array, 0, range(8))
        api = self.loaded.readiness.api
        self.assertEqual(api._array_copy(state, None, array, 0, array, 2, 6), 8)
        expected = bytes([0, 1, 0, 1, 2, 3, 4, 5])
        self.assertEqual(byte_values(state, state.cap_heap.read_slice(array, 0, 8), 'array'), expected)
        with self.assertRaisesRegex(HeapError, 'array_bounds'):
            api._array_copy(state, None, array, 0, array, 2, 7)
        self.assertEqual(byte_values(state, state.cap_heap.read_slice(array, 0, 8), 'array'), expected)

    def test_global_apdu_references_cannot_escape_to_persistent_fields(self):
        state = self.session.prepare_command(0x7f)
        receiver = state.javacard.registrations[self.session.aid]
        with self.assertRaisesRegex(HeapError, 'global_reference'):
            state.cap_heap.write_field(receiver, receiver.type, 'desKey', 'byte[]', state.javacard.buffer)
        refs = state.cap_heap.new_array('javacard.framework.APDU', 1)
        with self.assertRaisesRegex(HeapError, 'global_reference'):
            state.cap_heap.write_array(refs, 0, state.javacard.apdu)

    def test_api_binding_identity_and_unsupported_algorithms_are_checked(self):
        api = self.loaded.readiness.api
        ref = next(m for m in self.loaded.program.external_methods if m.name == 'setKey')
        with self.assertRaisesRegex(HeapError, 'api_binding'):
            api.lookup(replace(ref, name='wrongName'))
        with self.assertRaisesRegex(HeapError, 'api_unsupported'):
            api._cipher_instance(self.session.state.copy(), None, 99, 0)

    def test_unmodeled_interface_implementation_requires_cap_token_map(self):
        from pysoot_adapter import ClassMetadata
        from angr_integration.calls import CallResolver
        from angr_integration.heap_types import HeapSchema
        from angr_integration.readiness import walk
        api = self.loaded.readiness.api
        schema = HeapSchema(self.loaded.program, (*api.classes,
            ClassMetadata('custom.DESKey', 'java.lang.Object', ('javacard.security.DESKey',))))
        resolver = CallResolver(self.loaded.program, self.loaded.index, schema, api)
        node = next(n for m in self.loaded.program.methods.values() for b in m.blocks
                    for s in b.statements for n in walk(s) if type(n).__name__ == 'SootInterfaceInvokeExpr')
        with self.assertRaisesRegex(HeapError, 'interface_dispatch'):
            resolver.resolve(node, 'custom.DESKey')

    def test_dofinal_iv_reset_deselect_and_key_change_guard(self):
        self.send(0x20, 2, data=KEY)
        self.send(0x21, data=IV)
        end = self.send(0x22, 0, 1, PLAIN)
        cipher_ref = self.field(end, 'desCbcCipher', 'javacardx.crypto.Cipher')
        self.assertEqual(end.javacard.ciphers[cipher_ref.allocation_id].iv, (0,) * 8)
        key_ref = self.field(end, 'tempDesKey3', 'javacard.security.Key')
        copied = end.copy()
        self.loaded.readiness.api._set_key(copied, key_ref, self.field(copied, 'desKey', 'byte[]'), 0)
        with self.assertRaisesRegex(HeapError, 'api_unspecified'):
            self.loaded.readiness.api._cipher_final(copied, cipher_ref, copied.javacard.buffer, 0, 8, copied.javacard.buffer, 0)
        copied.javacard.deselect()
        self.assertIsNone(copied.javacard.keys[key_ref.allocation_id].data)
        self.assertIsNotNone(end.javacard.keys[key_ref.allocation_id].data)

    def test_step_budget_never_reports_success_or_updates_card_state(self):
        previous = self.session.state
        run = self.session.transmit(0x7f, max_steps=1)
        self.assertTrue(run.active)
        self.assertFalse(run.completed)
        self.assertIs(self.session.state, previous)

    def test_single_two_three_key_des_and_degenerate_key(self):
        # Standard single DES known-answer vector; triples with equal keys reduce to DES.
        key, plain, expected = (bytes.fromhex(s) for s in
                               ('133457799BBCDFF1', '0123456789ABCDEF', '85E813540F0AB405'))
        for expanded in (key, key * 2, key * 3):
            self.assertEqual(des_crypt(plain, expanded, 2, 5, bytes(8)), expected)
            self.assertEqual(des_crypt(expected, expanded, 1, 5, bytes(8)), plain)
        self.assertEqual(des_crypt(PLAIN, KEY, 2, 5, bytes(8)), ECB)
        for key in (KEY[:16], KEY):
            self.assertEqual(des_crypt(PLAIN, key, 2, 1, IV), DES3.new(key, DES3.MODE_CBC, iv=IV).encrypt(PLAIN))

    def test_deliverable_demo_checks_every_expected_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_demo(directory)
        self.assertEqual(len(result['scenarios']), 15)
        self.assertEqual(len(result['symbolic_p1']), 3)
        self.assertEqual(result['unexpected_errors'], 0)
        self.assertFalse(result['native_firmware_executed'])


if __name__ == '__main__':
    unittest.main()
