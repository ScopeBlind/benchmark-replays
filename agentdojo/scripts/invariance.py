#!/usr/bin/env python3
"""Invariance test (design section 2.6, rule 5).

Usage: python3 -I invariance.py <adapter.py> <runs_dir> <adapter_out_dir> <report_json> [sample_calls]

1. For every trace, recompute the request facts from message 1 alone (read
   again from the run file) and compare with what the adapter recorded.
2. Every (pipeline, suite, task, message 1) group must have exactly one
   request-facts hash, whatever the attack type or injection task.
3. Every (message 1, tool, args) combination must have exactly one facts
   value across all calls, whatever trace it came from.
4. For a seeded sample of calls, recompute the facts from the run file and
   compare byte for byte with the adapter output.
Exit 1 on any failure.
"""
import gzip
import hashlib
import importlib.util
import json
import os
import random
import sys
from collections import defaultdict


def load(path):
    spec = importlib.util.spec_from_file_location("adapter_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ad = load(sys.argv[1])
    runs, adir, out = sys.argv[2], sys.argv[3], sys.argv[4]
    sample_n = int(sys.argv[5]) if len(sys.argv) > 5 else 3000
    traces = {}
    with open(os.path.join(adir, "traces.jsonl"), encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            traces[r["t"]] = r
    failures = []
    requests = {}
    groups = defaultdict(set)
    for t, r in traces.items():
        p = os.path.join(runs, r["pipeline"], r["suite"], r["task"], r["attack"], r["file"])
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        msgs = d.get("messages") or []
        request = next((ad.text_of(m.get("content")) for m in msgs if m.get("role") == "user"), "")
        requests[t] = request
        if ad.sha(request) != r["msg1_sha256"]:
            failures.append(("msg1", t))
        rf = ad.sha(ad.canon(ad.request_view(request)))
        if rf != r["request_facts_sha256"]:
            failures.append(("request_facts", t))
        groups[(r["pipeline"], r["suite"], r["task"], r["msg1_sha256"])].add(r["request_facts_sha256"])
    multi = [k for k, v in groups.items() if len(v) != 1]
    failures += [("group", k) for k in multi]
    combo = defaultdict(set)
    rng = random.Random(20261025)
    sample = []
    seen = 0
    with gzip.open(os.path.join(adir, "calls.jsonl.gz"), "rt", encoding="utf-8") as f:
        for line in f:
            c = json.loads(line)
            key = hashlib.sha256((traces[c["t"]]["msg1_sha256"] + "\x00" + c["tool"] + "\x00" + ad.canon(c["args"])).encode()).hexdigest()
            combo[key].add(hashlib.sha256(ad.canon(c["facts"]).encode()).hexdigest())
            seen += 1
            if len(sample) < sample_n:
                sample.append(c)
            else:
                j = rng.randrange(seen)
                if j < sample_n:
                    sample[j] = c
    combo_bad = sum(1 for v in combo.values() if len(v) != 1)
    if combo_bad:
        failures.append(("combo", combo_bad))
    recomputed_bad = 0
    for c in sample:
        request = requests[c["t"]]
        r = traces[c["t"]]
        with open(os.path.join(runs, r["pipeline"], r["suite"], r["task"], r["attack"], r["file"]), encoding="utf-8") as f:
            msgs = json.load(f).get("messages") or []
        calls = []
        for m in msgs:
            if m.get("role") == "assistant":
                calls.extend(m.get("tool_calls") or [])
        tc = calls[c["i"]]
        args = tc.get("args")
        args = {} if args is None else args
        if str(tc.get("function") or "") != c["tool"] or ad.canon(args) != ad.canon(c["args"]):
            recomputed_bad += 1
            continue
        if ad.canon(ad.facts_for(request, c["tool"], args)) != ad.canon(c["facts"]):
            recomputed_bad += 1
    if recomputed_bad:
        failures.append(("recompute", recomputed_bad))
    res = {
        "traces": len(traces),
        "groups": len(groups),
        "groups_with_more_than_one_facts_value": len(multi),
        "distinct_msg1_tool_args_combinations": len(combo),
        "combinations_with_more_than_one_facts_value": combo_bad,
        "calls_seen": seen,
        "sample_recomputed": len(sample),
        "sample_mismatches": recomputed_bad,
        "failures": [list(map(str, x)) for x in failures[:50]],
        "result": "PASS" if not failures else "FAIL",
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
