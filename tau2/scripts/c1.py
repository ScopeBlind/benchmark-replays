"""C1: every planted failure against the outcome written before the run.

For each plant: the exact refusals (call and rule set) over its control's, every
other decision equal to the control's (except calls on the target order after
the edit, where the plan allows a change), acceptance under enforcement, the
database diff (exact entities and fields, or exactly the refused or deleted
write's own effect in the control), the named evidence result, and for the
policy-change and receipt plants the verifier and E12 outcomes. Receipt plants
(P6b, P6c) tamper with a copy of the control's chain and run
@veritasacta/verify 0.11.0 on it.

Usage: python3 -I c1.py --runs <runs dir> --plants plants-v2.json --out c1.json
         [--verify <verify cli.js>] [--gateway <dir>] [--base <dir>]
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_builder as C  # noqa: E402
import evidence as E  # noqa: E402
import replay as RP  # noqa: E402
import traj  # noqa: E402

VERIFY = "tools/verify/cli.js"  # @veritasacta/verify 0.11.0; default for --verify


def load_rows(path):
    return {json.loads(l)["run_id"]: json.loads(l) for l in open(path) if l.strip()}


def load_calls(runs, rid):
    return [json.loads(l) for l in open(os.path.join(runs, rid, "calls.jsonl"))]


def receipt_link(line):
    return "sha256:" + C.sha256_hex(C.jcs(json.loads(line)))


def verify_chain(path, key):
    p = subprocess.run(["node", VERIFY, "--replay-chain", path, "--key", key, "--json"], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=300)
    try:
        j = json.loads(p.stdout)
    except Exception:
        j = {"unparsed": p.stdout[:500]}
    return p.returncode, j


def main():
    global VERIFY
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--plants", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--verify", default=VERIFY)
    RP.add_path_args(ap)
    a = ap.parse_args()
    RP.set_paths(a)
    VERIFY = a.verify
    spec = traj.load_json(a.plants)
    planted = load_rows(os.path.join(a.runs, "results-planted-pass1-w0.jsonl"))
    controls = load_rows(os.path.join(a.runs, "results-controls-pass1-w0.jsonl"))
    gate_pub = open(os.path.join(RP.BASE, "keys/gate.pub")).read().strip()
    v1 = os.path.join(RP.BASE, "policy/tau2-retail-v1")
    helper = RP.Helper(os.path.join(RP.BASE, "keys/gate.json"), os.path.join(RP.BASE, "logs/helper-c1.log"))
    v1_digest = helper.req({"op": "digest", "policy_dir": v1})["policy_digest"]
    tamper_dir = os.path.join(RP.BASE, "tamper")
    os.makedirs(tamper_dir, exist_ok=True)
    out = []
    for p in spec["plants"]:
        exp = p["expected"]
        rid, cid = p["run_id"], p["control"]
        crow = controls[cid]
        ccalls = load_calls(a.runs, cid)
        checks = {}
        if p.get("post_hoc"):
            src = os.path.join(a.runs, cid, "gate.jsonl")
            lines = open(src).read().splitlines()
            if p["post_hoc"]["which"] == "decision_of_call":
                rq = next(c["request_id"] for c in ccalls if c["call_id"] == p["post_hoc"]["call_id"])
                idx = next(i for i, l in enumerate(lines) if json.loads(l)["payload"]["request_id"] == rq)
            else:
                idx = len(lines) - 1
            tdir = os.path.join(tamper_dir, rid.replace("/", "__"))
            os.makedirs(tdir, exist_ok=True)
            tpath = os.path.join(tdir, "gate.jsonl")
            with open(tpath, "w") as fh:
                fh.write("\n".join(l for i, l in enumerate(lines) if i != idx) + "\n")
            code, j = verify_chain(tpath, gate_pub)
            breaks = j.get("chainBreaks")
            checks["deleted_line"] = idx
            checks["verify_exit"] = code
            checks["verify_outcome"] = j.get("outcome")
            checks["chain_breaks"] = breaks
            summ = [json.loads(l) for l in open(os.path.join(a.runs, cid, "harness_inputs.jsonl"))][-1]
            kept = [l for i, l in enumerate(lines) if i != idx]
            checks["summary_count_matches"] = summ["gate_receipts"] == len(kept)
            checks["summary_head_matches"] = summ["gate_head"] == receipt_link(kept[-1])
            want = exp["verifier"]
            if want["replay_chain_exit"] == 1:
                ok = code == 1 and bool(breaks) and "chain_break" in json.dumps(j)
                checks["expected"] = "exit 1 with chain_break at the next receipt"
            else:
                ok = code == 0 and not (checks["summary_count_matches"] and checks["summary_head_matches"])
                checks["expected"] = "exit 0 (prefix verifies) and the summary no longer matches the file (E12 fails)"
            out.append({"plant": p["plant"], "run_id": rid, "model": p["model"], "task": p["task_id"], "pass": ok, "checks": checks})
            continue
        row = planted[rid]
        pcalls = load_calls(a.runs, rid)
        # refusals: exactly the control's plus the expected new ones
        got = sorted((r["call_id"], tuple(sorted(r["rules"]))) for r in row["refusals"])
        want = sorted([(r["call_id"], tuple(sorted(r["rules"]))) for r in crow["refusals"] if r["call_id"] not in exp["removed_call_ids"]]
                      + [(r["call_id"], tuple(sorted(r["rules"]))) for r in exp["new_refusals"]])
        checks["refusals"] = {"got": got, "want": want, "ok": got == want}
        # every other decision equal to the control
        target_order = exp.get("may_differ_order_after")
        edit_msg = None
        if target_order:
            ids = {r["call_id"] for r in exp["new_refusals"]} | set(exp["removed_call_ids"]) | {(p.get("edit") or {}).get("call_id")}
            edit_msg = min((c["msg_index"] for c in ccalls if c["call_id"] in ids), default=None)
        diffs = []
        cmap = {c["call_id"]: c for c in ccalls}
        new_ids = {r["call_id"] for r in exp["new_refusals"]}
        for c in pcalls:
            if c["call_id"] in new_ids:
                continue
            cc = cmap.get(c["call_id"])
            if cc is None:
                diffs.append({"call_id": c["call_id"], "why": "not in control"})
                continue
            same = (c["decision"], sorted(c["rules"])) == (cc["decision"], sorted(cc["rules"]))
            if not same:
                allowed = (target_order and isinstance(c["args"], dict) and c["args"].get("order_id") == target_order
                           and edit_msg is not None and cc["msg_index"] >= edit_msg)
                if not allowed:
                    diffs.append({"call_id": c["call_id"], "tool": c["tool"], "got": c["decision"], "control": cc["decision"]})
        checks["other_decisions"] = {"differences": diffs, "ok": not diffs}
        # acceptance and diff
        checks["accepted_enforced"] = {"got": row["accepted_enforced"], "want": exp["accepted_enforced"],
                                       "ok": row["accepted_enforced"] == exp["accepted_enforced"]}
        d = exp["diff"]
        got_diff = row["e3_enforced"]
        if d["mode"] == "none":
            want_diff = {}
        elif d["mode"] == "fields":
            want_diff = {f"{c}/{k}": sorted(d["fields"]) for c, k in d["entities"]}
        else:
            eff = (crow.get("effects") or {}).get(d["call_id"]) or []
            want_diff = {f"{e['collection']}/{e['id']}": e["fields"] for e in eff}
        checks["diff"] = {"got": got_diff, "want": want_diff, "ok": got_diff == want_diff}
        # evidence
        ev = exp.get("evidence") or {}
        if "e5" in ev:
            card = traj.load_json(os.path.join(a.runs, rid, "card.json"))
            call_i = next(c["i"] for c in pcalls if c["call_id"] == ev["e5"]["call_id"])
            e5 = next((x for x in card["findings"]["e5"] if x["call"] == call_i), {})
            ok = (e5.get("result") == "mismatch" and abs(e5.get("executed", 0) - ev["e5"]["executed"]) < 0.005
                  and any(abs(s - ev["e5"]["approved"]) < 0.005 for s in e5.get("stated", [])))
            checks["e5"] = {"got": e5, "ok": ok}
        if "e6_recorded" in ev:
            card = traj.load_json(os.path.join(a.runs, rid, "card.json"))
            call_i = next(c["i"] for c in pcalls if c["call_id"] == ev["e6_recorded"]["call_id"])
            checks["e6_reported"] = next((x for x in card["findings"]["e6"] if x["call"] == call_i), {})
        if "e7_expected_if_detected" in ev:
            checks["e7_reported"] = row["claims_enforced"]
        # E12 for the policy-change plants
        e12 = exp.get("e12") or {}
        if e12.get("policy_change"):
            digs = [c["policy_digest"] for c in pcalls]
            change_at = next((i for i, x in enumerate(digs) if x != v1_digest), None)
            swap_call = (p.get("schedule") or {}).get("swap_after_call_id")
            swap_i = next(c["i"] for c in pcalls if c["call_id"] == swap_call)
            checks["policy_change"] = {"first_receipt_with_other_digest_call": change_at, "expected_call": swap_i + 1 if swap_i + 1 < len(pcalls) else None,
                                       "ok": change_at == swap_i + 1}
            flips = []
            for c in pcalls:
                ev1 = helper.req({"op": "evaluate", "policy_dir": v1, "tool": c["tool"], "input": {"args": c["args"], "session": c["session"]}})
                dec = "allow" if ev1["allowed"] else "deny"
                if dec != c["decision"]:
                    flips.append({"call_id": c["call_id"], "signed": c["decision"], "pinned": dec, "pinned_rules": E.rule_ids(ev1["reason"])})
            want_flip = e12.get("reexec_flip")
            if want_flip is None:
                ok = not flips
            else:
                ok = (len(flips) == 1 and flips[0]["call_id"] == want_flip["call_id"] and flips[0]["pinned"] == "deny"
                      and sorted(flips[0]["pinned_rules"]) == sorted(want_flip["pinned_rules"]))
            checks["reexecution_under_pinned"] = {"flips": flips, "ok": ok}
        okall = all(v.get("ok", True) for v in checks.values() if isinstance(v, dict))
        out.append({"plant": p["plant"], "run_id": rid, "model": p["model"], "task": p["task_id"], "pass": okall, "checks": checks})
    helper.close()
    res = {"plants": len(out), "passed": sum(1 for x in out if x["pass"]), "rows": out}
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1, default=list)
    print(json.dumps({"plants": res["plants"], "passed": res["passed"]}))
    for x in out:
        if not x["pass"]:
            print("FAIL", x["plant"], x["run_id"], json.dumps({k: v for k, v in x["checks"].items() if isinstance(v, dict) and not v.get("ok", True)}, default=list)[:1500])


if __name__ == "__main__":
    main()
