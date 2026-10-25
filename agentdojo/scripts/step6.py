#!/usr/bin/env python3
"""Step 6: equivalence sample (M7) and signed sample (M8 inputs).

Usage:
  python3 -I step6.py sample      <out_root>
  python3 -I step6.py equivalence <out_root> <gateway_cli_js> <key_file>
  python3 -I step6.py bundle      <out_root> <gateway_cli_js> <key_file>

<out_root> is the experiment output directory (holds adapter/, decisions/,
report/, run/policies/). Seed 20261025. Every CLI call runs one at a time,
with stdin closed and arguments passed as a list (no shell). The key file's
secret half is never read here; only the CLI reads it.
"""
import gzip
import json
import os
import random
import subprocess
import sys
import time
from collections import defaultdict

SUITES = ("banking", "slack", "travel", "workspace")
SEED = 20261025


def load_calls(root, wanted):
    out = {}
    with gzip.open(os.path.join(root, "adapter", "calls.jsonl.gz"), "rt", encoding="utf-8") as f:
        for line in f:
            c = json.loads(line)
            if (c["t"], c["i"]) in wanted:
                out[(c["t"], c["i"])] = c
    return out


def load_decisions(root, wanted):
    out = {}
    with gzip.open(os.path.join(root, "decisions", "decisions.jsonl.gz"), "rt", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            if d["v"] == "full" and (d["t"], d["i"]) in wanted:
                out[(d["t"], d["i"])] = d
    return out


def load_traces(root):
    tr = {}
    with open(os.path.join(root, "adapter", "traces.jsonl"), encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            tr[r["t"]] = r
    return tr


def spread(rng, items, k, group_index):
    """Pick k items round-robin over groups (shuffled), so every group is used before any repeats."""
    groups = defaultdict(list)
    for it in items:
        groups[it[group_index]].append(it)
    keys = sorted(groups)
    for g in keys:
        rng.shuffle(groups[g])
    rng.shuffle(keys)
    picked = []
    while len(picked) < k and any(groups[g] for g in keys):
        for g in keys:
            if groups[g] and len(picked) < k:
                picked.append(groups[g].pop())
    return picked


def cmd_sample(root):
    pools = json.load(open(os.path.join(root, "report", "pools.json")))
    res = json.load(open(os.path.join(root, "report", "results.json")))
    expected_fb = {(x["trace"], x["call_index"]) for x in res["false_blocks_full"] if x["expected"]}
    rng = random.Random(SEED)
    equiv, bundle = [], []
    for s in SUITES:
        p = pools[s]
        fa = [tuple(x[:2]) for x in rng.sample(p["first_attacker"], 25)]
        hp = [tuple(x) for x in rng.sample(p["hplus"], 25)]
        taken = set(fa) | set(hp)
        rest = [tuple(x) for x in p["all"] if tuple(x) not in taken]
        al = [tuple(x) for x in rng.sample(rest, 25)]
        equiv += [(s, "first_attacker", x) for x in fa] + [(s, "hplus", x) for x in hp] + [(s, "random", x) for x in al]
    rng = random.Random(SEED)
    for s in SUITES:
        p = pools[s]
        fa = [tuple(x[:2]) for x in spread(rng, p["first_attacker"], 25, 2)]
        fbs = sorted([tuple(x) for x in p["hplus_false_block"] if tuple(x) in expected_fb])
        rng.shuffle(fbs)
        fbs = fbs[:5]
        hrest = [tuple(x) for x in p["hplus"] if tuple(x) not in set(fbs)]
        hp = fbs + [tuple(x) for x in rng.sample(hrest, 15 - len(fbs))]
        cp = [tuple(x[:2]) for x in spread(rng, p["cplus_sink"], 10, 2)]
        bundle += [(s, "first_attacker", x) for x in fa] + [(s, "hplus", x) for x in hp] + [(s, "cplus_sink", x) for x in cp]
    wanted = {x for _, _, x in equiv + bundle}
    calls = load_calls(root, wanted)
    decs = load_decisions(root, wanted)
    tr = load_traces(root)

    def item(s, stratum, key):
        c, d, r = calls[key], decs[key], tr[key[0]]
        return {"suite": s, "stratum": stratum, "t": key[0], "i": key[1], "tool": c["tool"], "args": c["args"], "facts": c["facts"],
                "trace": "/".join((r["pipeline"], r["suite"], r["task"], r["attack"], r["file"])),
                "library_allowed": d["a"], "library_class": d["c"], "library_rules": d["r"]}

    os.makedirs(os.path.join(root, "equivalence"), exist_ok=True)
    os.makedirs(os.path.join(root, "bundle"), exist_ok=True)
    with open(os.path.join(root, "equivalence", "sample.json"), "w", encoding="utf-8") as f:
        json.dump([item(*e) for e in equiv], f, indent=0)
    with open(os.path.join(root, "bundle", "sample.json"), "w", encoding="utf-8") as f:
        json.dump([item(*e) for e in bundle], f, indent=0)
    print(json.dumps({"equivalence": len(equiv), "bundle": len(bundle),
                      "bundle_expected_false_blocks": sum(1 for s, st, x in bundle if x in expected_fb)}))


def rule_ids(reason):
    if not reason or not reason.startswith("cedar_deny: "):
        return ""
    return "+".join(part.split(": ", 1)[0] for part in reason[len("cedar_deny: "):].split("; "))


def run(argv):
    t0 = time.time()
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr, time.time() - t0


def last_receipt(path):
    with open(path, encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    return json.loads(lines[-1]), len(lines)


def cmd_equivalence(root, cli, key):
    sample = json.load(open(os.path.join(root, "equivalence", "sample.json")))
    rdir = os.path.join(root, "equivalence", "receipts")
    os.makedirs(rdir, exist_ok=True)
    rows, agree, rule_agree, n_deny = [], 0, 0, 0
    t_eval = t_sign = 0.0
    for it in sample:
        pol = os.path.join(root, "run", "policies", it["suite"], "full")
        inp, ctx = json.dumps(it["args"], ensure_ascii=True), json.dumps(it["facts"], ensure_ascii=True)
        rc, out, err, dt = run(["node", cli, "evaluate", "--cedar", pol, "--tool", it["tool"], "--input", inp, "--context", ctx])
        t_eval += dt
        ev = json.loads(out.strip().splitlines()[0]) if out.strip() else {}
        eval_allowed = rc == 0 and ev.get("allowed") is True
        eval_ok_exit = rc in (0, 2)
        rc2, out2, err2, dt2 = run(["node", cli, "sign", "--cedar", pol, "--tool", it["tool"], "--input", inp, "--context", ctx,
                                    "--receipts", rdir, "--key", key])
        t_sign += dt2
        so = json.loads(out2.strip().splitlines()[-1]) if out2.strip() else {}
        rec, _ = last_receipt(os.path.join(rdir, "receipts.jsonl"))
        pay = rec.get("payload", {})
        lib = "allow" if it["library_allowed"] else "deny"
        ev_d = "allow" if eval_allowed else "deny"
        same = lib == ev_d == so.get("decision") == pay.get("decision") and eval_ok_exit and rc2 == 0
        agree += same
        if lib == "deny":
            n_deny += 1
            ids_same = it["library_rules"] == rule_ids(ev.get("reason")) == rule_ids(pay.get("reason"))
            rule_agree += ids_same
        rows.append({"suite": it["suite"], "stratum": it["stratum"], "trace": it["trace"], "i": it["i"], "tool": it["tool"],
                     "library": lib, "evaluate_exit": rc, "evaluate": ev_d, "sign_stdout": so.get("decision"),
                     "receipt": pay.get("decision"), "agree": same, "library_rules": it["library_rules"],
                     "evaluate_rules": rule_ids(ev.get("reason")), "receipt_rules": rule_ids(pay.get("reason")),
                     "evaluate_digest": ev.get("policy_digest"), "receipt_digest": pay.get("policy_digest")})
    digests_consistent = all(r["evaluate_digest"] == r["receipt_digest"] for r in rows)
    res = {"n": len(rows), "decision_agreement": agree, "denies": n_deny, "deny_rule_id_agreement": rule_agree,
           "digests_consistent": digests_consistent, "by_suite_library_decisions": {},
           "seconds_evaluate": round(t_eval, 1), "seconds_sign": round(t_sign, 1),
           "disagreements": [r for r in rows if not r["agree"]]}
    for s in SUITES:
        sub = [r for r in rows if r["suite"] == s]
        res["by_suite_library_decisions"][s] = {"allow": sum(r["library"] == "allow" for r in sub), "deny": sum(r["library"] == "deny" for r in sub)}
    with open(os.path.join(root, "equivalence", "rows.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=0)
    with open(os.path.join(root, "equivalence", "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "disagreements"}, indent=1), "disagreements:", len(res["disagreements"]))


def cmd_bundle(root, cli, key):
    sample = json.load(open(os.path.join(root, "bundle", "sample.json")))
    rdir = os.path.join(root, "bundle", "receipts")
    os.makedirs(rdir, exist_ok=True)
    items = []
    t_sign = 0.0
    for n, it in enumerate(sample):
        pol = os.path.join(root, "run", "policies", it["suite"], "full")
        inp, ctx = json.dumps(it["args"], ensure_ascii=True), json.dumps(it["facts"], ensure_ascii=True)
        rc, out, err, dt = run(["node", cli, "sign", "--cedar", pol, "--tool", it["tool"], "--input", inp, "--context", ctx,
                                "--receipts", rdir, "--key", key])
        t_sign += dt
        so = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        rec, nlines = last_receipt(os.path.join(rdir, "receipts.jsonl"))
        items.append({"receipt_line": nlines, "suite": it["suite"], "stratum": it["stratum"], "trace": it["trace"], "call_index": it["i"],
                      "tool": it["tool"], "input": it["args"], "facts": it["facts"], "policy_dir": f"run/policies/{it['suite']}/full",
                      "library_decision": "allow" if it["library_allowed"] else "deny", "library_rules": it["library_rules"],
                      "sign_exit": rc, "signed": so.get("signed"), "receipt_decision": rec.get("payload", {}).get("decision"),
                      "request_id": rec.get("payload", {}).get("request_id")})
    with open(os.path.join(root, "bundle", "items.jsonl"), "w", encoding="utf-8") as f:
        for x in items:
            f.write(json.dumps(x, ensure_ascii=True, sort_keys=True) + "\n")
    res = {"n": len(items), "sign_exit_zero": sum(x["sign_exit"] == 0 for x in items), "signed": sum(bool(x["signed"]) for x in items),
           "receipt_matches_library": sum(x["receipt_decision"] == x["library_decision"] for x in items),
           "denies": sum(x["library_decision"] == "deny" for x in items), "seconds_sign": round(t_sign, 1)}
    with open(os.path.join(root, "bundle", "sign_results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd == "sample":
        cmd_sample(root)
    elif cmd == "equivalence":
        cmd_equivalence(root, sys.argv[3], sys.argv[4])
    elif cmd == "bundle":
        cmd_bundle(root, sys.argv[3], sys.argv[4])
    else:
        raise SystemExit("unknown command")


if __name__ == "__main__":
    main()
