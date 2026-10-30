"""Find the call on name1.java:66 using symbolic APDU bytes and the real CAP.

Run from the project root:
    python find_name1_line66.py
    python find_name1_line66.py --length 16
    python find_name1_line66.py --selecting

This is a worked example for the supplied, unchanged name1 CAP, not a general
Java source-line debugger. Length/receive_length and the selection context are
concrete harness parameters; CLA, INS, P1, P2 and every data byte are symbolic.
"""
import argparse
import hashlib
import json
from pathlib import Path

from angr import claripy

from angr_integration.javacard_session import JavaCardSession
from angr_integration.name1_demo import FIXTURE, load_name1


CAP_SHA256 = "edd4d74faea6ff1e37309bb0e6bf2bb35e94d97061c1f99c80f9766765941b65"
OWNER = "name1.name1"
APDU = "javacard.framework.APDU"


def analyze(length=24, *, selecting=False, receive_length=None, max_steps=200):
    if type(length) is not int or not 0 <= length <= 255:
        raise ValueError("length must be in 0..255")
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be positive")
    received = length if receive_length is None else receive_length
    if type(received) is not int or not 0 <= received <= length:
        raise ValueError("receive_length must be in 0..length")
    if hashlib.sha256((FIXTURE / "name1.cap").read_bytes()).hexdigest() != CAP_SHA256:
        raise ValueError("This example maps line 66 only for the original name1.cap")
    if (FIXTURE / "name1.java").read_text().splitlines()[65].strip() != "setDesKey(apdu, len);":
        raise ValueError("Java line 66 changed; review the source-to-call mapping")

    loaded = load_name1()
    session = JavaCardSession(loaded)
    session.install()  # Execute constructor/install; do not fabricate an applet.

    process_key = loaded.index.by_signature[(OWNER, "process", (APDU,))]
    target_key = loaded.index.by_signature[(OWNER, "setDesKey", (APDU, "short"))]
    callsites = [stmt for block in loaded.program.methods[process_key].blocks
                 for stmt in block.statements
                 if type(stmt).__name__ == "InvokeStmt"
                 and stmt.invoke_expr.class_name == OWNER
                 and stmt.invoke_expr.method_name == "setDesKey"
                 and tuple(stmt.invoke_expr.method_params) == (APDU, "short")]
    if len(callsites) != 1:
        raise ValueError("Expected the single process -> setDesKey call from line 66")
    callsite = loaded.index.by_label[process_key, callsites[0].label]
    target = loaded.method_address(target_key)

    # The solver, rather than a preset INS=0x20, must select the target branch.
    cla, ins, p1, p2 = [claripy.BVS(name, 8, explicit_name=True)
                        for name in ("CLA", "INS", "P1", "P2")]
    data = tuple(claripy.BVS(f"DATA_{i:02d}", 8, explicit_name=True)
                 for i in range(length))
    initial = session.prepare_command(ins, p1, p2, data, cla=cla,
                                      selecting=selecting, receive_length=received)
    packet = claripy.Concat(cla, ins, p1, p2, claripy.BVV(length, 8), *data)

    # The call itself is inside a Soot block. Stop at the callee's entry, which
    # proves the call was taken, without relying on a mid-block breakpoint.
    manager = loaded.project.factory.simgr(initial)
    manager.explore(find=lambda state: state.addr == target, n=max_steps)
    report = {
        "schema": "name1.line66.example/1",
        "cap_sha256": CAP_SHA256,
        "source": {"file": "examples/name1/name1.java", "line": 66,
                   "statement": "setDesKey(apdu, len);"},
        "callsite": callsite.to_dict(),
        "target_key": target_key,
        "target_address": str(target),
        "context": {"selectingApplet": selecting, "Lc": length,
                    "received_len": received, "max_steps": max_steps},
        "symbolic": ["CLA", "INS", "P1", "P2", f"DATA[0:{length}]"],
        "search": {"found": len(manager.found), "active": len(manager.active),
                   "deadended": len(manager.deadended),
                   "errors": [str(e.error) for e in manager.errored]},
    }
    if not manager.found:
        report["reachability"] = ("not_found_within_budget_or_model_error"
                                  if manager.active or manager.errored else "unreachable")
        return report

    hit = manager.found[0]
    guard = claripy.And(*hit.solver.constraints)
    expected = ins == 0x20
    # Verify both implications. A single witness is not a complete condition.
    only_ins20 = not hit.solver.satisfiable(extra_constraints=[~expected])
    all_ins20 = not initial.solver.satisfiable(extra_constraints=[expected, ~guard])
    if not only_ins20 or not all_ins20:
        raise RuntimeError("Reachability differs from INS == 0x20; inspect the CAP/model")
    report.update({
        "reachability": "reached",
        "path_constraints": [str(c) for c in hit.solver.constraints],
        "condition_in_fixed_context": "INS == 0x20; CLA/P1/P2/DATA unrestricted",
        "condition_equivalence_checked": True,
        "allowed_ins": hit.solver.eval_upto(ins, 257),
        # One solver model for the WHOLE packet, not unrelated byte witnesses.
        "reach_packet_hex": hit.solver.eval(packet, cast_to=bytes).hex(" ").upper(),
    })

    # A second question: what happens AFTER reaching the call?
    continuation = session.run(hit.copy(), max_steps=max_steps)
    outcomes = []
    for end in continuation.completed:
        values = end.solver.eval_upto(end.javacard.status, 2)
        if len(values) != 1:
            raise RuntimeError("This report expects a concrete SW on each path")
        outcomes.append({
            "sw": f"{values[0]:04X}",
            "p1_values": sorted(end.solver.eval_upto(p1, 257)),
            "constraints": [str(c) for c in end.solver.constraints],
            "packet_hex": end.solver.eval(packet, cast_to=bytes).hex(" ").upper(),
        })
    report["after_call"] = {
        "outcomes": sorted(outcomes, key=lambda row: (row["sw"], row["p1_values"])),
        "errors": [str(e.error) for e in continuation.errored],
        "active": len(continuation.active),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--length", type=int, default=24,
                        help="Concrete input byte count / Lc, 0..255")
    parser.add_argument("--receive-length", type=int,
                        help="Bytes returned by the first receive (default: all)")
    parser.add_argument("--selecting", action="store_true",
                        help="Set selectingApplet()=true: process returns before line 66")
    parser.add_argument("--max-steps", type=int, default=200)
    parser.add_argument("--output", type=Path, default=Path("outputs/name1_line66/result.json"))
    args = parser.parse_args()
    report = analyze(args.length, selecting=args.selecting,
                     receive_length=args.receive_length, max_steps=args.max_steps)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Java line 66: {report['reachability']}")
    print(f"Context: {report['context']}")
    print(f"CAP callsite: process offset {report['callsite']['cap_offset']}, "
          f"Unit {report['callsite']['unit_label']}")
    if report["reachability"] == "reached":
        print(f"Condition: {report['condition_in_fixed_context']}")
        print(f"Constraints: {report['path_constraints']}")
        print(f"Reach witness: {report['reach_packet_hex']}")
        print("Continuation from setDesKey entry:")
        for outcome in report["after_call"]["outcomes"]:
            vals = outcome["p1_values"]
            short = ", ".join(f"{v:02X}" for v in vals) if len(vals) <= 8 else f"{len(vals)} values (see JSON)"
            print(f"  SW={outcome['sw']}; P1={short}")
            if outcome["sw"] == "9000":
                print(f"  Successful APDU: {outcome['packet_hex']}")
        print(f"Continuation errors={len(report['after_call']['errors'])}; "
              f"active={report['after_call']['active']}")
    print(f"Report: {args.output.resolve()}")
    # No claim of completion if a budget or model error stopped the requested work.
    incomplete = report["reachability"] == "not_found_within_budget_or_model_error"
    incomplete |= bool(report.get("after_call", {}).get("errors"))
    incomplete |= bool(report.get("after_call", {}).get("active"))
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
