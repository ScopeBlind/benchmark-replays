"""Check that the signed receipts commit to the published inputs (standard library only).

This does not check signatures; @veritasacta/verify does that. It recomputes
what each receipt's payload_digest binds and compares:

  AgentDojo (bundle/ and equivalence/): sha256 over the JCS bytes of each
    call's arguments as recorded, and their byte length, against the receipt;
    tool name, decision and policy digest against the published sample.
  tau2 (run directories): for every call in calls.jsonl, the decision
    receipt's input hash over JCS({"args", "session"}) and its tool, decision
    and policy digest; for every executed call, the result digest and the
    observation receipt's input hash; every harness receipt against
    harness_inputs.jsonl; and the run summary's gate receipt count and head
    (the chain link of the last gate receipt).

Usage:
  python3 -I tools/check_receipt_inputs.py --agentdojo agentdojo
  python3 -I tools/check_receipt_inputs.py --tau2 <run dir> [<run dir> ...]
"""
import decimal
import hashlib
import json
import math
import os
import sys


def num(x):
    """ECMAScript Number-to-String, as RFC 8785 requires for numbers."""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS has no NaN or Infinity")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    t = decimal.Decimal(repr(abs(x))).normalize().as_tuple()
    digits = "".join(map(str, t.digits))
    k = len(digits)
    n = k + t.exponent  # value = 0.digits * 10**n
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + s


def jcs(v):
    if v is None or isinstance(v, bool) or isinstance(v, (int, float)):
        return "null" if v is None else num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v).__name__)


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def agentdojo(root):
    problems = 0
    items = lines(os.path.join(root, "bundle", "items.jsonl"))
    rec = lines(os.path.join(root, "bundle", "receipts", "receipts.jsonl"))
    for it in items:
        p = rec[it["receipt_line"] - 1]["payload"]
        c = jcs(it["input"])
        ok = (p["payload_digest"]["input_hash"] == sha(c) and p["payload_digest"]["input_size"] == len(c.encode("utf-8"))
              and p["tool_name"] == it["tool"] and p["decision"] == it["receipt_decision"])
        problems += not ok
    print(f"agentdojo bundle: {len(items)} receipts checked, problems {problems}")
    sample = json.load(open(os.path.join(root, "equivalence", "sample.json")))
    rows = json.load(open(os.path.join(root, "equivalence", "rows.json")))
    erec = lines(os.path.join(root, "equivalence", "receipts", "receipts.jsonl"))
    p2 = 0
    if not (len(sample) == len(rows) == len(erec)):
        raise SystemExit("equivalence files do not line up")
    for s, r, e in zip(sample, rows, erec):
        p = e["payload"]
        c = jcs(s["args"])
        ok = (p["payload_digest"]["input_hash"] == sha(c) and p["tool_name"] == s["tool"] == r["tool"]
              and p["decision"] == r["receipt"] and p["policy_digest"] == r["receipt_digest"])
        p2 += not ok
    print(f"agentdojo equivalence: {len(erec)} receipts checked, problems {p2}")
    return problems + p2


def tau2(run_dirs):
    problems = decisions = 0
    for d in run_dirs:
        calls = lines(os.path.join(d, "calls.jsonl"))
        gate = lines(os.path.join(d, "gate.jsonl"))
        hin = lines(os.path.join(d, "harness_inputs.jsonl"))
        hrec = [x["payload"] for x in lines(os.path.join(d, "harness.jsonl"))]
        k = 0
        for c in calls:
            p = gate[k]["payload"]
            k += 1
            decisions += 1
            ok = (p["payload_digest"]["input_hash"] == sha(jcs({"args": c["args"], "session": c["session"]}))
                  and (p["tool_name"], p["decision"], p["policy_digest"]) == (c["tool"], c["decision"], c["policy_digest"]))
            if c["executed"]:
                o = gate[k]["payload"]
                k += 1
                obs = {"request_id": c["request_id"], "result_sha256": c["result_sha256"], "error": c["result_error"],
                       "source": c["result_source"]}
                ok = ok and sha(c["result"]) == c["result_sha256"] and o["payload_digest"]["input_hash"] == sha(jcs(obs))
            problems += not ok
        problems += k != len(gate)
        problems += len(hrec) != len(hin) or any(r["payload_digest"]["input_hash"] != sha(jcs(x)) for r, x in zip(hrec, hin))
        head = "sha256:" + sha(jcs(gate[-1])) if gate else None
        problems += (hin[-1]["gate_receipts"], hin[-1]["gate_head"]) != (len(gate), head)
    print(f"tau2: {len(run_dirs)} runs, {decisions} decisions checked, problems {problems}")
    return problems


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--agentdojo":
        bad = agentdojo(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--tau2":
        bad = tau2(sys.argv[2:])
    else:
        raise SystemExit(__doc__)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
