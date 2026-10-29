"""Execute the unchanged name1 CAP with an explicit Java Card API profile."""
import argparse
import hashlib
import json
from pathlib import Path

from .javacard_session import JavaCardSession
from .javacard_api import byte_values, integer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'examples' / 'name1'
# NIST SP 800-67 Appendix B.1 (also reproduced in PyCryptodome's DES3 tests).
KEY = bytes.fromhex('0123456789abcdef23456789abcdef01456789abcdef0123')
PLAIN = bytes.fromhex('54686520717566636b2062726f776e20666f78206a756d70')
ECB = bytes.fromhex('a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900')
IV = bytes.fromhex('0102030405060708')


def load_name1(cap_path=FIXTURE/'name1.cap', symbols_path=FIXTURE/'symbols.json'):
    from main import (load_cap, extract_methods, build_cfgs, verify_methods, build_jcvm_ir,
                      build_jvm_like_ir, load_symbols, build_soot_ir, build_pysoot_model, load_angr_program)
    cap = load_cap(Path(cap_path))
    methods, symbols = extract_methods(cap), load_symbols(Path(symbols_path))
    verify_methods(methods)
    jcvm = build_jcvm_ir(cap, methods, build_cfgs(methods), interface_signatures=symbols.interface_signatures)
    program = build_pysoot_model(cap, build_soot_ir(build_jvm_like_ir(jcvm), symbols), symbols)
    return load_angr_program(program, api_profile='name1')


def run_demo(output_root, cap_path=FIXTURE/'name1.cap', symbols_path=FIXTURE/'symbols.json'):
    loaded = load_name1(cap_path, symbols_path)
    session = JavaCardSession(loaded)
    install = session.install().summary()
    scenarios = []
    def command(name, ins, p1=0, p2=0, data=b'', sw=0x9000, response=None, **kwargs):
        result = session.transmit(ins, p1, p2, data, **kwargs)
        if result.errored or result.active or len(result.completed) != 1:
            raise RuntimeError(f'{name}: unexpected outcome {result.summary()}')
        end = result.completed[0]
        if integer(end, end.javacard.status, 'SW', signed=False) != sw:
            raise RuntimeError(f'{name}: wrong SW {result.summary()}')
        actual = byte_values(end, end.javacard.response, 'APDU response')
        if response is not None and actual != response:
            raise RuntimeError(f'{name}: wrong response {actual.hex()}')
        scenarios.append({'name': name, 'expected_sw': f'{sw:04X}', **result.summary()})
        return actual

    command('select', 0xa4, selecting=True)
    command('unsupported_ins', 0x7f, sw=0x6d00)
    command('cipher_before_key', 0x22, data=bytes(8), sw=0x6985)
    command('invalid_key_p1', 0x20, 3, data=KEY, sw=0x6a86)
    command('wrong_key_length', 0x20, 2, data=KEY[:16], sw=0x6700)
    command('wrong_iv_length', 0x21, data=IV[:7], sw=0x6700)
    command('partial_receive', 0x20, 2, data=KEY, receive_length=8, sw=0x6700)
    command('unaligned_cipher_input', 0x22, data=PLAIN[:7], sw=0x6700)

    # Explore every P1 value without selecting one for execution.
    p1 = loaded.dependencies.claripy.BVS('name1_key_p1', 8, explicit_name=True)
    symbolic = session.run(session.prepare_command(0x20, p1, data=KEY))
    if symbolic.errored or symbolic.active or len(symbolic.completed) != 3:
        raise RuntimeError(f'Unexpected symbolic outcomes: {symbolic.summary()}')
    symbolic_paths = []
    for end in symbolic.completed:
        sw = integer(end, end.javacard.status, 'SW', signed=False)
        expected = {0x9000: p1 == 2, 0x6700: p1 == 1, 0x6a86: (p1 != 1) & (p1 != 2)}.get(sw)
        if expected is None or end.solver.satisfiable(extra_constraints=[~expected]):
            raise RuntimeError('Symbolic P1 path has incorrect constraints')
        guard = loaded.dependencies.claripy.And(*end.solver.constraints)
        if session.state.solver.satisfiable(extra_constraints=[expected, ~guard]):
            raise RuntimeError('Symbolic P1 exploration lost valid inputs')
        symbolic_paths.append({'sw': f'{sw:04X}', 'p1_witness': end.solver.eval(p1),
                               'constraints': [str(c) for c in end.solver.constraints]})

    command('set_24_byte_key', 0x20, 2, data=KEY)
    command('set_iv', 0x21, data=IV)
    encrypted = command('ecb_nist_known_answer', 0x22, data=PLAIN, response=ECB)
    command('ecb_decrypt', 0x22, 1, data=encrypted, response=PLAIN)
    encrypted = command('cbc_encrypt', 0x22, 0, 1, PLAIN)
    command('cbc_decrypt', 0x22, 1, 1, encrypted, response=PLAIN)
    command('set_16_byte_key', 0x20, 1, data=KEY[:16])
    fault = session.transmit(0x22, data=PLAIN[:8])
    if fault.completed or fault.active or len(fault.errored) != 1:
        raise RuntimeError('Expected exactly one null-receiver fault')
    error = fault.errored[0].error
    if getattr(error, 'code', None) != 'null_reference' or error.source.cap_offset != 41:
        raise RuntimeError(f'Unexpected negative-test failure: {error}')

    result = {'api_profile': loaded.readiness.api.name,
              'cap_sha256': hashlib.sha256(Path(cap_path).read_bytes()).hexdigest(),
              'execution': 'Original CAP bytecode through angr Soot with explicit Python API models',
              'native_firmware_executed': False,
              'crypto_inputs': 'Concrete only; symbolic control flow is supported',
              'install': install, 'scenarios': scenarios,
              'symbolic_p1': sorted(symbolic_paths, key=lambda p: p['sw']),
              'expected_null_receiver_fault': fault.summary(), 'unexpected_errors': 0}
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    loaded.export(output_root/'loader')
    (output_root/'execution.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cap', type=Path, default=FIXTURE/'name1.cap')
    parser.add_argument('--symbols', type=Path, default=FIXTURE/'symbols.json')
    parser.add_argument('--output-root', type=Path, default=ROOT/'outputs'/'name1_execution')
    args = parser.parse_args()
    result = run_demo(args.output_root, args.cap, args.symbols)
    print('install: OK; applet AID 11223344556600')
    print(f'APDU scenarios passed: {len(result["scenarios"])}')
    print('DES ECB known-answer and ECB/CBC round-trip: OK')
    print(f'Symbolic P1 completed paths: {len(result["symbolic_p1"])}')
    print('Expected null receiver: getDesKey, CAP offset 41')
    print(f'Report: {(args.output_root / "execution.json").resolve()}')


if __name__ == '__main__':
    main()
