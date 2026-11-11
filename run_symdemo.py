"""Reproducible experiments on the supplied symdemo CAP; see docs/guides/symdemo.md.

Run from the project root: python run_symdemo.py all
The Java source is explanatory; execution uses the original CAP through angr.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / 'examples' / 'symdemo'
CAP_SHA256 = '29e72750b5662cb3a71ce035c829f73c8de2b722114dbef968a14c512cab06fa'
PACKAGE = 'f053594d44454d4f@1.0'
OWNER = 'symdemo.symdemo'
APDU = 'javacard.framework.APDU'
METHODS = {1: '<init>', 8: 'install', 30: 'process', 137: 'receiveExact',
           182: 'runRare', 430: 'runOverflow', 522: 'runImpossible',
           597: 'targetRare', 608: 'targetOverflow', 619: 'targetImpossible', 630: 'sendResult'}
SCENARIOS = {'rare': (0x10, 8, 'targetRare'),
             'overflow': (0x20, 2, 'targetOverflow'),
             'impossible': (0x30, 2, 'targetImpossible')}


def load_symdemo(cap_path=FIXTURE / 'symdemo.cap', symbols_path=FIXTURE / 'symbols.json'):
    from main import (load_cap, extract_methods, load_symbols, verify_methods, build_cfgs,
                      build_jcvm_ir, build_jvm_like_ir, build_soot_ir, build_pysoot_model,
                      load_angr_program)
    if hashlib.sha256(Path(cap_path).read_bytes()).hexdigest() != CAP_SHA256:
        raise ValueError('Different symdemo CAP: regenerate/review method bindings before removing the hash guard')
    cap = load_cap(Path(cap_path))
    methods, symbols = extract_methods(cap), load_symbols(Path(symbols_path))
    if symbols.class_names.get(PACKAGE + ':o2') != OWNER:
        raise ValueError('Expected the compiled class symdemo.symdemo at class offset 2')
    for offset, name in METHODS.items():
        if symbols.method_names.get(f'{PACKAGE}:internal:t6:o{offset}') != name:
            raise ValueError(f'Wrong method binding at offset {offset}: expected {name}')
    verify_methods(methods)
    jcvm = build_jcvm_ir(cap, methods, build_cfgs(methods),
                        interface_signatures=symbols.interface_signatures)
    soot = build_soot_ir(build_jvm_like_ir(jcvm), symbols)
    program = build_pysoot_model(cap, soot, symbols)
    return load_angr_program(program, api_profile='symdemo')


def new_session(loaded, max_steps=500):
    from angr_integration.javacard_session import JavaCardSession
    session = JavaCardSession(loaded)
    session.install(max_steps=max_steps)
    return session


def inspect(loaded):
    report = loaded.to_dict()
    return {'schema': 'symdemo.inspect/1', 'cap_sha256': CAP_SHA256,
            'owner': OWNER, 'api_profile': report['api_profile'],
            'versions': report['versions'], 'applets': report['applets'],
            'unresolved_symbols': report['unresolved_symbols'],
            'methods': report['methods'], 'api_models': report['api_models']}


def concrete(session, ins=0x20, data=b'\x00\x01', *, cla=0x80, p1=0, p2=0,
             selecting=False, receive_length=None, max_steps=500):
    result = session.run(session.prepare_command(ins, p1, p2, data, cla=cla,
                         selecting=selecting, receive_length=receive_length), max_steps=max_steps)
    packet = bytes((cla, ins, p1, p2, len(data))) + bytes(data)
    return {'schema': 'symdemo.concrete/1', 'cap_sha256': CAP_SHA256,
            'packet_without_le_hex': packet.hex(' ').upper(),
            'case4_apdu_hex': (packet + b'\x02').hex(' ').upper(),
            'selectingApplet': selecting,
            'received_len': len(data) if receive_length is None else receive_length,
            **result.summary()}


def expected_condition(claripy, scenario, header, data, selecting, received):
    """Independent source-level oracle, used AFTER exploration, never as an input constraint."""
    ins, length, _ = SCENARIOS[scenario]
    if selecting or len(data) != length or received != length:
        return claripy.BoolV(False)
    cla, instruction, p1, p2 = header
    valid_header = claripy.And(cla == 0x80, instruction == ins, p1 == 0, p2 == 0)
    if scenario == 'impossible':
        return claripy.BoolV(False)
    if scenario == 'overflow':
        amount = claripy.Concat(*data)
        return claripy.And(valid_header, amount.UGE(2768), amount.ULE(10000))
    a, b, c, d, e, f, g, h = [claripy.ZeroExt(8, byte) for byte in data]
    return claripy.And(valid_header, a+b == 220, b^c == 0x58, c+d == 303,
                       d^e == 0xdb, e+f == 253, f^g == 0xb6, g+h == 221,
                       a^h == 0x2c, a+b+c+d+e+f+g+h == 997)


def callsites(loaded, target_name):
    result = []
    for key, method in loaded.program.methods.items():
        for block in method.blocks:
            for stmt in block.statements:
                if type(stmt).__name__ != 'InvokeStmt':
                    continue
                call = stmt.invoke_expr
                if call.class_name == OWNER and call.method_name == target_name:
                    result.append(loaded.index.by_label[key, stmt.label].to_dict())
    return result


def analyze(session, scenario, *, symbolic_header=False, length=None,
            receive_length=None, selecting=False, max_steps=500):
    if max_steps < 1:
        raise ValueError('max_steps must be positive')
    loaded = session.loaded
    claripy = loaded.dependencies.claripy
    ins, default_length, target_name = SCENARIOS[scenario]
    length = default_length if length is None else length
    if not 0 <= length <= 255:
        raise ValueError('length must be between 0 and 255')
    received = length if receive_length is None else receive_length
    if not 0 <= received <= length:
        raise ValueError('receive_length must be between zero and length')
    header = ([claripy.BVS(f'{scenario}_{name}', 8, explicit_name=True)
               for name in ('CLA', 'INS', 'P1', 'P2')] if symbolic_header else
              [claripy.BVV(value, 8) for value in (0x80, ins, 0, 0)])
    data = tuple(claripy.BVS(f'{scenario}_DATA_{i:02d}', 8, explicit_name=True)
                 for i in range(length))
    initial = session.prepare_command(header[1], header[2], header[3], data, cla=header[0],
                                      selecting=selecting, receive_length=received)
    packet = claripy.Concat(*header, claripy.BVV(length, 8), *data)
    key = loaded.index.by_signature[(OWNER, target_name, (APDU,))]
    target = loaded.method_address(key)
    manager = loaded.project.factory.simgr(initial)
    rounds = 0
    # Stop each matching path at the callee entry, but finish every other path.
    # A first hit alone is insufficient for enumerating/proving the full condition.
    while True:
        manager.move(from_stash='active', to_stash='found',
                     filter_func=lambda state: state.addr == target)
        if not manager.active or rounds >= max_steps:
            break
        manager.step()
        rounds += 1
    other = {name: len(states) for name, states in manager.stashes.items()
             if states and name not in ('active', 'found', 'deadended', 'unsat')}
    errors = [str(record.error) for record in manager.errored]
    complete = not manager.active and not errors and not other
    found = manager.stashes.get('found', [])
    report = {'schema': 'symdemo.symbolic/1', 'cap_sha256': CAP_SHA256,
              'scenario': scenario, 'api_profile': loaded.readiness.api.name,
              'target_key': key, 'target_address': str(target),
              'callsites': callsites(loaded, target_name),
              'context': {'symbolic_header': symbolic_header, 'selectingApplet': selecting,
                          'Lc': length, 'received_len': received, 'max_steps': max_steps},
              'symbolic': ([str(v) for v in header] if symbolic_header else []) + [str(v) for v in data],
              'search': {'found': len(found), 'deadended': len(manager.deadended),
                         'active': len(manager.active), 'errors': errors, 'other_stashes': other,
                         'step_rounds': rounds, 'complete': complete},
              'reachability': 'reached' if found else ('unreachable_in_model' if complete else 'unknown'),
              'found_path_constraints': [[str(c) for c in state.solver.constraints] for state in found],
              'condition_equivalence_checked': False}
    guard = claripy.Or(*(claripy.And(*state.solver.constraints) for state in found))
    if complete:
        expected = expected_condition(claripy, scenario, header, data, selecting, received)
        mismatch = claripy.Or(claripy.And(guard, ~expected), claripy.And(expected, ~guard))
        report['condition_equivalence_checked'] = not initial.solver.satisfiable(extra_constraints=[mismatch])
        if not report['condition_equivalence_checked']:
            report['model_mismatch'] = 'CAP reachability differs from the independent source-level condition'
    report['continuations'] = [session.run(state.copy(), max_steps=max_steps).summary() for state in found]
    if found:
        combined = initial.copy()
        combined.solver.add(guard)
        # Select a single consistent model for the ENTIRE packet, deterministically.
        witness = combined.solver.min(packet).to_bytes(5 + length, 'big')
        report['packet_without_le_hex'] = witness.hex(' ').upper()
        report['case4_apdu_hex'] = (witness + b'\x02').hex(' ').upper()
        report['replay'] = concrete(session, witness[1], witness[5:], cla=witness[0],
                                    p1=witness[2], p2=witness[3], selecting=selecting,
                                    receive_length=received, max_steps=max_steps)
        if scenario == 'rare':
            packets = sorted(combined.solver.eval_upto(packet, 9, cast_to=bytes))
            report['enumeration_complete'] = complete and len(packets) < 9
            report['matching_apdus'] = [(p + b'\x02').hex(' ').upper() for p in packets]
        if scenario == 'overflow' and length == 2:
            amount = claripy.Concat(*data)
            report['unsigned_amount_min'] = combined.solver.min(amount)
            report['unsigned_amount_max'] = combined.solver.max(amount)
            report['amount_interval_exact'] = complete and report['condition_equivalence_checked']
    return report


def fully_checked(report):
    if report.get('model_mismatch'):
        return False
    if 'search' in report and not report['search']['complete']:
        return False
    if report.get('errors') or report.get('active_paths'):
        return False
    return all(not r['errors'] and not r['active_paths'] for r in report.get('continuations', [])) and (
        'replay' not in report or fully_checked(report['replay']))


def hex_byte(value):
    number = int(value, 16)
    if not 0 <= number <= 255:
        raise argparse.ArgumentTypeError('expected a hex byte, 00..FF')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'concrete', 'rare', 'overflow', 'impossible', 'all'))
    parser.add_argument('--cap', type=Path, default=FIXTURE / 'symdemo.cap')
    parser.add_argument('--symbols', type=Path, default=FIXTURE / 'symbols.json')
    parser.add_argument('--output-root', type=Path, default=ROOT / 'outputs' / 'symdemo_execution')
    parser.add_argument('--max-steps', type=int, default=500)
    parser.add_argument('--symbolic-header', action='store_true')
    parser.add_argument('--length', type=int, help='Concrete Lc for a symbolic experiment')
    parser.add_argument('--receive-length', type=int)
    parser.add_argument('--selecting', action='store_true')
    parser.add_argument('--ins', type=hex_byte, default=0x20, help='Concrete command INS, hexadecimal')
    parser.add_argument('--cla', type=hex_byte, default=0x80)
    parser.add_argument('--p1', type=hex_byte, default=0)
    parser.add_argument('--p2', type=hex_byte, default=0)
    parser.add_argument('--data', default='00 01', help='Concrete command data, hexadecimal')
    args = parser.parse_args()
    if args.max_steps < 1:
        parser.error('--max-steps must be positive')
    if args.command == 'concrete' and (args.symbolic_header or args.length is not None):
        parser.error('--symbolic-header/--length are for symbolic experiments; --data determines concrete Lc')
    loaded = load_symdemo(args.cap, args.symbols)
    args.output_root.mkdir(parents=True, exist_ok=True)
    loaded.export(args.output_root / 'loader')
    reports = {'inspect': inspect(loaded)}
    if args.command != 'inspect':
        # Installation gets its own budget; a small search budget need not break install.
        session = new_session(loaded)
        print(f'install: OK; applet AID {session.aid.hex().upper()}')
        if args.command in ('concrete', 'all'):
            reports['concrete'] = concrete(session, args.ins, bytes.fromhex(args.data), cla=args.cla,
                                           p1=args.p1, p2=args.p2, selecting=args.selecting,
                                           receive_length=args.receive_length, max_steps=args.max_steps)
        for scenario in (SCENARIOS if args.command == 'all' else (args.command,)):
            if scenario in SCENARIOS:
                reports[scenario] = analyze(session, scenario, symbolic_header=args.symbolic_header,
                                            length=args.length, receive_length=args.receive_length,
                                            selecting=args.selecting, max_steps=args.max_steps)
    for name, report in reports.items():
        destination = args.output_root / (name + '.json')
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        if name == 'inspect':
            ready = sum(m['execution_ready'] for m in report['methods'])
            print(f'inspect: methods={len(report["methods"])}; ready={ready}; unresolved={len(report["unresolved_symbols"])}')
        elif name == 'concrete':
            print(f'concrete: {report["completed"]}; errors={len(report["errors"])}; active={report["active_paths"]}')
        else:
            s = report['search']
            print(f'{name}: {report["reachability"]}; found={s["found"]}; active={s["active"]}; errors={len(s["errors"])}; complete={s["complete"]}')
            print(f'  condition equivalence: {report["condition_equivalence_checked"]}')
            if 'case4_apdu_hex' in report:
                print(f'  APDU: {report["case4_apdu_hex"]}')
            if name == 'rare' and 'matching_apdus' in report:
                print(f'  matching inputs: {len(report["matching_apdus"])}; enumeration complete={report["enumeration_complete"]}')
            if 'unsigned_amount_min' in report:
                print(f'  amount: {report["unsigned_amount_min"]}..{report["unsigned_amount_max"]}; exact={report["amount_interval_exact"]}')
        print(f'  Report: {destination.resolve()}')
    return 0 if all(fully_checked(report) for report in reports.values()) else 2


if __name__ == '__main__':
    raise SystemExit(main())
