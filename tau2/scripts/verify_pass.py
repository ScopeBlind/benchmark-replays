"""Step 5 (C3): verify every run's receipts offline and re-derive what they bind.

1. @veritasacta/verify 0.11.0 `--replay-chain` with the pinned keys: each planted
   and control run's two chains on their own; the published runs' chains
   concatenated per model (each run's first receipt starts a new chain, so the
   verifier counts one chain per run). verify checks signatures and links only.
2. For every run, independently of verify: every chain link; every decision
   receipt's fields against calls.jsonl; every input hash recomputed from the
   disclosed {args, session}; every observation receipt over the disclosed
   result; the policy digest each decision carries; the harness read-backs and
   the summary (receipt count and head of the gate chain).
3. Decision re-execution with protect-mcp's own evaluator (library mode) on the
   disclosed input, under the policy the receipt names and under the pinned v1.
4. The 2% CLI cross-check: for a fixed random 2% of published runs, every
   decision again through `protect-mcp sign --cedar` and `protect-mcp evaluate`.
5. The tamper set on four runs: a flipped decision, a deleted receipt, a wrong key.

Usage: python3 -I verify_pass.py --runs <dir> --out c3.json [--verify <verify cli.js>]
         [--gateway <dir>] [--base <dir>]
"""
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_builder as C  # noqa: E402
import evidence as E  # noqa: E402
import replay as RP  # noqa: E402
import traj  # noqa: E402

VERIFY = "tools/verify/cli.js"  # @veritasacta/verify 0.11.0; default for --verify
CLI = None  # <gateway>/dist/cli.js, set in main() from --gateway


def link(line):
    return "sha256:" + C.sha256_hex(C.jcs(json.loads(line)))


def verify(path, key):
    p = subprocess.run(["node", VERIFY, "--replay-chain", path, "--key", key, "--json"], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=1800)
    try:
        j = json.loads(p.stdout)
    except Exception:
        j = {"unparsed": p.stdout[:300], "stderr": p.stderr[:300]}
    return p.returncode, {k: j.get(k) for k in ("outcome", "verified", "failed", "undecidable", "chains", "total", "valid", "chainBreaks")}, j


def check_run(rdir, pdirs, digest_to_dir, helper, v1_dir):
    calls = [json.loads(l) for l in open(os.path.join(rdir, "calls.jsonl"))]
    glines = open(os.path.join(rdir, "gate.jsonl")).read().splitlines()
    hlines = open(os.path.join(rdir, "harness.jsonl")).read().splitlines()
    hin = [json.loads(l) for l in open(os.path.join(rdir, "harness_inputs.jsonl"))]
    prob = []
    for lines, name in ((glines, "gate"), (hlines, "harness")):
        for i, l in enumerate(lines):
            p = json.loads(l)["payload"]
            want = link(lines[i - 1]) if i > 0 else None
            if p.get("previousReceiptHash") != want:
                prob.append(f"{name} link {i}")
    expected = len(calls) + sum(1 for c in calls if c["executed"])
    if len(glines) != expected:
        prob.append(f"gate receipt count {len(glines)} != {expected}")
    k = 0
    reexec_own = reexec_pinned_flips = 0
    for c in calls:
        p = json.loads(glines[k])["payload"]
        k += 1
        gi = {"args": c["args"], "session": c["session"]}
        ih = C.sha256_hex(C.jcs(gi))
        if (p["tool_name"], p["decision"], p["policy_digest"], p["request_id"]) != (c["tool"], c["decision"], c["policy_digest"], c["request_id"]):
            prob.append(f"decision fields call {c['i']}")
        want_reason = "cedar_allow" if c["decision"] == "allow" else c["reason"]
        if p["reason"] != want_reason:
            prob.append(f"reason call {c['i']}")
        if p["payload_digest"]["input_hash"] != ih or ih != c["gate_input_sha256"]:
            prob.append(f"input hash call {c['i']}")
        own_dir = digest_to_dir.get(p["policy_digest"])
        ev = helper.req({"op": "evaluate", "policy_dir": own_dir, "tool": c["tool"], "input": gi})
        dec = "allow" if ev["allowed"] else "deny"
        if dec != c["decision"] or (dec == "deny" and ev["reason"] != c["reason"]):
            prob.append(f"re-execution under own policy call {c['i']}")
        else:
            reexec_own += 1
        if own_dir != v1_dir:
            ev1 = helper.req({"op": "evaluate", "policy_dir": v1_dir, "tool": c["tool"], "input": gi})
            if ("allow" if ev1["allowed"] else "deny") != c["decision"]:
                reexec_pinned_flips += 1
        if c["executed"]:
            o = json.loads(glines[k])["payload"]
            k += 1
            if C.sha256_hex(c["result"]) != c["result_sha256"]:
                prob.append(f"result digest call {c['i']}")
            oi = {"request_id": c["request_id"], "result_sha256": c["result_sha256"], "error": c["result_error"], "source": c["result_source"]}
            if o["tool_name"] != f"{c['tool']}.observed" or o["payload_digest"]["input_hash"] != C.sha256_hex(C.jcs(oi)) or o["request_id"] != c["observation_request_id"]:
                prob.append(f"observation call {c['i']}")
    if len(hlines) != len(hin):
        prob.append("harness count")
    for l, obj in zip(hlines, hin):
        if json.loads(l)["payload"]["payload_digest"]["input_hash"] != C.sha256_hex(C.jcs(obj)):
            prob.append(f"harness input {obj.get('entity') or 'summary'}")
    summ = hin[-1]
    head = link(glines[-1]) if glines else None
    if summ.get("gate_receipts") != len(glines) or summ.get("gate_head") != head:
        prob.append("summary does not bind the gate chain")
    digests = sorted({c["policy_digest"] for c in calls})
    return {"problems": prob, "calls": len(calls), "gate_receipts": len(glines), "harness_receipts": len(hlines),
            "reexec_own_ok": reexec_own, "reexec_pinned_flips": reexec_pinned_flips, "policy_digests": digests}


def cli_crosscheck(rdir, v1_dir, gate_key, empty_dir):
    calls = [json.loads(l) for l in open(os.path.join(rdir, "calls.jsonl"))]
    glines = open(os.path.join(rdir, "gate.jsonl")).read().splitlines()
    dec_lines = []
    k = 0
    for c in calls:
        dec_lines.append(json.loads(glines[k])["payload"])
        k += 2 if c["executed"] else 1
    out = {"decisions": 0, "sign_match": 0, "evaluate_match": 0, "mismatches": []}
    tmp = tempfile.mkdtemp(prefix="cli-", dir=empty_dir)
    for c, lp in zip(calls, dec_lines):
        gi = json.dumps({"args": c["args"], "session": c["session"]})
        s = subprocess.run(["node", CLI, "sign", "--cedar", v1_dir, "--tool", c["tool"], "--input", gi, "--receipts", tmp,
                            "--key", gate_key, "--dir", empty_dir], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        sj = json.loads(next(l for l in s.stdout.splitlines() if l.strip().startswith("{")))
        last = open(os.path.join(tmp, "receipts.jsonl")).read().splitlines()[-1]
        sp = json.loads(last)["payload"]
        e = subprocess.run(["node", CLI, "evaluate", "--cedar", v1_dir, "--tool", c["tool"], "--input", gi],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        ej = json.loads(next(l for l in e.stdout.splitlines() if l.strip().startswith("{")))
        out["decisions"] += 1
        sign_ok = (sj["decision"], sj["policy_digest"], sp["reason"], sp["payload_digest"]["input_hash"]) == \
                  (lp["decision"], lp["policy_digest"], lp["reason"], lp["payload_digest"]["input_hash"])
        ev_dec = "allow" if e.returncode == 0 else ("deny" if e.returncode == 2 else "error")
        eval_ok = ev_dec == lp["decision"] and (ev_dec == "allow" or ej.get("reason") == lp["reason"])
        out["sign_match"] += sign_ok
        out["evaluate_match"] += eval_ok
        if not (sign_ok and eval_ok):
            out["mismatches"].append({"run": rdir, "call": c["i"], "tool": c["tool"], "lib": lp["decision"], "cli_sign": sj["decision"], "cli_eval": ev_dec})
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def main():
    global VERIFY, CLI
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cli-fraction", type=float, default=0.02)
    ap.add_argument("--seed", type=int, default=20261025)
    ap.add_argument("--verify", default=VERIFY)
    RP.add_path_args(ap)
    a = ap.parse_args()
    RP.set_paths(a)
    VERIFY, CLI = a.verify, os.path.join(RP.GATEWAY, "dist/cli.js")
    B = RP.BASE
    gate_pub = open(os.path.join(B, "keys/gate.pub")).read().strip()
    harness_pub = open(os.path.join(B, "keys/harness.pub")).read().strip()
    helper = RP.Helper(os.path.join(B, "keys/gate.json"), os.path.join(B, "logs/helper-verify.log"))
    pdirs = {lbl: os.path.join(B, "policy", d) for lbl, d in (("v1", "tau2-retail-v1"), ("p5a", "tau2-retail-v1-p5a"), ("p5b", "tau2-retail-v1-p5b"))}
    digest_to_dir = {helper.req({"op": "digest", "policy_dir": d})["policy_digest"]: d for d in pdirs.values()}
    res = {"runs": {}, "verify": {}, "cli": None, "tamper": {}}
    sets = {}
    for f in sorted(os.listdir(a.runs)):
        if f.startswith("results-") and f.endswith(".jsonl") and "-pass1-" in f:
            kind = f.split("-")[1]
            for l in open(os.path.join(a.runs, f)):
                r = json.loads(l)
                sets.setdefault(kind, []).append(r)
    tmp_root = os.path.join(B, "verify")
    os.makedirs(tmp_root, exist_ok=True)
    # 1+2+3: per-run checks; verify per run for planted and controls; concatenated for published
    for kind, rows in sets.items():
        rows.sort(key=lambda r: r["run_id"])
        bad = 0
        stats = {"runs": len(rows), "problem_runs": 0, "calls": 0, "reexec_own_ok": 0, "reexec_pinned_flips": 0, "examples": []}
        for r in rows:
            cr = check_run(os.path.join(a.runs, r["run_id"]), pdirs, digest_to_dir, helper, pdirs["v1"])
            stats["calls"] += cr["calls"]
            stats["reexec_own_ok"] += cr["reexec_own_ok"]
            stats["reexec_pinned_flips"] += cr["reexec_pinned_flips"]
            if cr["problems"]:
                stats["problem_runs"] += 1
                if len(stats["examples"]) < 10:
                    stats["examples"].append({"run": r["run_id"], "problems": cr["problems"][:5]})
        res["runs"][kind] = stats
        if kind in ("planted", "controls"):
            vstats = {"gate_exit0": 0, "harness_exit0": 0, "runs": 0, "other": []}
            for r in rows:
                rd = os.path.join(a.runs, r["run_id"])
                c1, s1, _ = verify(os.path.join(rd, "gate.jsonl"), gate_pub)
                c2, s2, _ = verify(os.path.join(rd, "harness.jsonl"), harness_pub)
                vstats["runs"] += 1
                vstats["gate_exit0"] += c1 == 0
                vstats["harness_exit0"] += c2 == 0
                if c1 != 0 or c2 != 0:
                    vstats["other"].append({"run": r["run_id"], "gate": [c1, s1], "harness": [c2, s2]})
            res["verify"][kind] = vstats
        else:
            by_model = {}
            for r in rows:
                by_model.setdefault(r["model"], []).append(r)
            res["verify"][kind] = {}
            for m, rs in by_model.items():
                for chain, key in (("gate", gate_pub), ("harness", harness_pub)):
                    cat = os.path.join(tmp_root, f"{kind}-{m}-{chain}.jsonl")
                    with open(cat, "w") as out:
                        for r in rs:
                            with open(os.path.join(a.runs, r["run_id"], f"{chain}.jsonl")) as fh:
                                out.write(fh.read())
                    code, summ, _ = verify(cat, key)
                    res["verify"][kind][f"{m}/{chain}"] = {"exit": code, **summ, "runs": len(rs),
                                                            "chainBreaks": len(summ["chainBreaks"]) if isinstance(summ.get("chainBreaks"), list) else summ.get("chainBreaks")}
                    os.remove(cat)
    # 4: the 2% CLI cross-check on published runs
    pub = sorted(sets.get("published", []), key=lambda r: r["run_id"])
    rnd = random.Random(a.seed)
    sample = rnd.sample(pub, max(1, int(round(len(pub) * a.cli_fraction)))) if pub else []
    empty = tempfile.mkdtemp(prefix="cli-empty-", dir=tmp_root)
    agg = {"runs": len(sample), "decisions": 0, "sign_match": 0, "evaluate_match": 0, "mismatches": []}
    for r in sample:
        x = cli_crosscheck(os.path.join(a.runs, r["run_id"]), pdirs["v1"], os.path.join(B, "keys/gate.json"), empty)
        for kk in ("decisions", "sign_match", "evaluate_match"):
            agg[kk] += x[kk]
        agg["mismatches"] += x["mismatches"]
    shutil.rmtree(empty, ignore_errors=True)
    res["cli"] = agg
    # 5: the tamper set on four controls (one per model)
    ctrl = sorted(sets.get("controls", []), key=lambda r: r["run_id"])
    picks = []
    for m in traj.MODELS:
        x = next((r for r in ctrl if r["model"] == m and not r["run_id"].endswith("_approval")), None)
        if x:
            picks.append(x)
    tam = []
    for r in picks:
        src = os.path.join(a.runs, r["run_id"], "gate.jsonl")
        lines = open(src).read().splitlines()
        d = os.path.join(tmp_root, "tamper-" + r["run_id"].replace("/", "__"))
        os.makedirs(d, exist_ok=True)
        flipped = json.loads(lines[0])
        flipped["payload"]["decision"] = "deny" if flipped["payload"]["decision"] == "allow" else "allow"
        with open(os.path.join(d, "flipped.jsonl"), "w") as fh:
            fh.write("\n".join([json.dumps(flipped)] + lines[1:]) + "\n")
        with open(os.path.join(d, "deleted.jsonl"), "w") as fh:
            fh.write("\n".join([lines[0]] + lines[2:]) + "\n")
        c1, s1, j1 = verify(os.path.join(d, "flipped.jsonl"), gate_pub)
        c2, s2, j2 = verify(os.path.join(d, "deleted.jsonl"), gate_pub)
        c3, s3, j3 = verify(src, harness_pub)
        tam.append({"run": r["run_id"],
                    "flipped": {"exit": c1, "outcome": s1.get("outcome"), "invalid_signature": "invalid_signature" in json.dumps(j1)},
                    "deleted": {"exit": c2, "outcome": s2.get("outcome"), "chain_break": "chain_break" in json.dumps(j2)},
                    "wrong_key": {"exit": c3, "outcome": s3.get("outcome"), "key_mismatch": "key_mismatch" in json.dumps(j3)}})
    res["tamper"] = tam
    helper.close()
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps({k: res[k] for k in ("runs", "verify", "cli")}, indent=1)[:6000])
    print(json.dumps(res["tamper"], indent=1))


if __name__ == "__main__":
    main()
