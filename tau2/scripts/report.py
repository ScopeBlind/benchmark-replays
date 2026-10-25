"""Aggregate C0 to C5 and write the report (plain ASCII).

C2: a refused write in a run that passes the database-only key is grounded
only when every rule that refused it has a passing mechanical test (G1 missing
read, G2 argument contradicting a recorded observation; G3, an argument outside
a closed list in the quoted line, is counted separately as an extension) on the
recorded transcript. A refusal that the recorded facts would have allowed is a
cascade of an earlier refusal and takes its root's grounding. The strict count
(any refused write in a passing run) is reported beside the split.

Usage: python3 -I report.py --base <out dir> [--data <tau2-bench data/tau2 dir>]
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import retail_env as R  # noqa: E402
import traj  # noqa: E402

READS = {"get_order_details", "get_user_details", "get_product_details", "get_item_details", "find_user_id_by_email",
         "find_user_id_by_name_zip", "list_all_product_types", "calculate", "transfer_to_human_agents"}


def rows(path):
    out = []
    for f in sorted(os.listdir(path)):
        if f.startswith("results-published-pass1-") and f.endswith(".jsonl"):
            out += [json.loads(l) for l in open(os.path.join(path, f)) if l.strip()]
    return out


def grounded_of(ref, earlier):
    if ref["first_order"]:
        tests = [g for g in ref["grounding"]]
        if tests and all(g["grounded"] for g in tests):
            return ("grounded_G3" if any(g["test"] == "G3" for g in tests) else "grounded"), tests
        return "ungrounded", tests
    root = next((e for e in earlier if e["first_order"]), None)
    if root is None:
        return "ungrounded", [{"note": "cascade with no first-order refusal before it"}]
    g, _ = grounded_of(root, [])
    return g + "_cascade", [{"note": f"follows the refusal at call {root['call']} ({','.join(root['rules'])})"}]


def enrich(cases, results_dir):
    """Attach the recorded tool result of each refused call (did the tool itself reject it?)."""
    D = results_dir
    need = {c["sim_id"] for c in cases}
    rec = {}
    for f in sorted(os.listdir(D)):
        if "_retail_" not in f or not f.endswith(".json"):
            continue
        data = traj.load_json(os.path.join(D, f))
        for sim in data["simulations"]:
            if sim["id"] in need:
                for st in traj.extract_steps(sim["messages"]):
                    rec[(sim["id"], st["i"])] = (bool(st["rec_error"]), (st["rec_content"] or "")[:90])
        del data
    for c in cases:
        err, head = rec[(c["sim_id"], c["call"])]
        c["recorded_tool_error"] = err
        c["recorded_result_head"] = head if err else None


def write_listing(B, w, r):
    lines = ["Refusals in published runs that pass the database-only answer key (v1.0.1 tasks).",
             "Columns: model | task trial | call | tool | rules | class | test | policy.md line | quote | evidence | recorded tool result",
             "Quotes are short excerpts of tau2-bench policy.md (MIT licence, copyright Sierra).", ""]

    def fmt(c):
        t = c["tests"][0] if c["tests"] else {}
        rec = ("tool also rejected it: " + (c.get("recorded_result_head") or "")) if c.get("recorded_tool_error") else "ran in the recording"
        return " | ".join([c["model"], f"task {c['task']} trial {c['trial']}", f"call {c['call']}", c["tool"], ",".join(c["rules"]), c["class"],
                           t.get("test", ""), t.get("policy_line", ""), t.get("quote", ""), (t.get("evidence") or t.get("note") or ""), rec])
    order = sorted(w, key=lambda c: (bool(c.get("recorded_tool_error")), ",".join(c["rules"]), c["model"], int(c["task"]), c["trial"], c["call"]))
    lines.append(f"REFUSED WRITES: {len(w)} (state-changing in the recording first)")
    lines += [fmt(c) for c in order]
    lines += ["", f"REFUSED READS: {len(r)}"] + [fmt(c) for c in r]
    with open(os.path.join(B, "reports/c2_listing.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--data", default="upstream/tau2-bench/data/tau2")
    a = ap.parse_args()
    B = a.base
    rs = rows(os.path.join(B, "runs"))
    rep = {}
    # ---------------------------------------------------------------- C2 and C4
    c2_cases, c2_reads = [], []
    per = defaultdict(lambda: defaultdict(Counter))
    claims_status = defaultdict(Counter)
    for r in rs:
        m = r["model"]
        passing = r["accepted_recorded"]
        side = "pass" if passing else "fail"
        P = per[m]
        P["runs"][side] += 1
        refs = r["refusals"]
        if refs:
            P["runs_with_refusal"][side] += 1
        for k, x in enumerate(refs):
            kind = "write" if x["tool"] not in READS else "read"
            for rule in x["rules"]:
                P["refusals_by_rule"][f"{side}/{kind}/{rule}"] += 1
            P["refusal_order"][f"{side}/{'first' if x['first_order'] else 'cascade'}"] += 1
            if passing:
                g, tests = grounded_of(x, refs[:k])
                case = {"run_id": r["run_id"], "sim_id": r["sim_id"], "task": r["task_id"], "trial": r["trial"], "model": m,
                        "call": x["call"], "tool": x["tool"], "rules": x["rules"], "first_order": x["first_order"],
                        "class": g, "tests": tests}
                (c2_cases if kind == "write" else c2_reads).append(case)
        if r["e4_not_established"]:
            P["e4_runs_with_unconfirmed_write"][side] += 1
        for x in r["e5"]:
            P["e5"][f"{side}/{x['result']}"] += 1
        for x in r["e6"]:
            P["e6"][f"{side}/{x['result']}"] += 1
        if r["e8"]["turns_with_several_calls"]:
            P["e8_runs_several_calls_in_a_turn"][side] += 1
        if r["e8"]["turns_with_text_and_call"]:
            P["e8_runs_text_with_call"][side] += 1
        if r["e10_not_established"]:
            P["e10_runs_reason_not_stated"][side] += 1
        for f in r["e13"]:
            P["e13"][f"{side}/{f['flag']}"] += 1
        false_claims = [c for c in r["claims_recorded"] if c["status"] != "observed"]
        for c in r["claims_recorded"]:
            claims_status[m][f"{side}/{c['status']}"] += 1
        if r["claims_recorded"]:
            P["runs_with_claim"][side] += 1
        if false_claims:
            P["runs_with_false_claim"][side] += 1
        finding = bool(refs or r["e4_not_established"] or any(x["result"] == "mismatch" for x in r["e5"] + r["e6"])
                       or r["e10_not_established"] or r["e13"] or false_claims)
        if not passing and not finding:
            P["failures_only_answer_key_sees"]["fail"] += 1
        if not passing and not refs:
            P["failures_without_refusal"]["fail"] += 1
    strict = len(c2_cases)
    split = Counter(c["class"] for c in c2_cases)
    controls = [json.loads(l) for l in open(os.path.join(B, "runs/results-controls-pass1-w0.jsonl"))]
    ctrl_refused_writes = sum(1 for r in controls for x in r["refusals"] if x["tool"] not in READS)
    ungrounded = [c for c in c2_cases if c["class"].startswith("ungrounded")]
    rep["C2"] = {"passing_published_runs": sum(1 for r in rs if r["accepted_recorded"]), "controls": len(controls),
                 "control_refused_writes": ctrl_refused_writes,
                 "strict_refused_writes_in_passing_runs": strict,
                 "strict_runs_with_refused_write": len({c["run_id"] for c in c2_cases}),
                 "split": dict(split), "ungrounded": len(ungrounded) + ctrl_refused_writes,
                 "refused_reads_in_passing_runs": len(c2_reads), "refused_reads_split": dict(Counter(c["class"] for c in c2_reads)),
                 "pass": len(ungrounded) == 0 and ctrl_refused_writes == 0}
    enrich(c2_cases + c2_reads, os.path.join(a.data, "results/final"))
    rep["C2"]["refused_writes_tool_also_rejected_in_recording"] = sum(1 for c in c2_cases if c["recorded_tool_error"])
    rep["C2"]["refused_writes_that_ran_in_recording"] = sum(1 for c in c2_cases if not c["recorded_tool_error"])
    rep["C2"]["passing_runs_not_reaching_gold_under_enforcement"] = sum(1 for r in rs if r["accepted_recorded"] and not r["accepted_enforced"])
    with open(os.path.join(B, "reports/c2_refused_writes_in_passing_runs.json"), "w") as fh:
        json.dump(c2_cases, fh, indent=1)
    with open(os.path.join(B, "reports/c2_refused_reads_in_passing_runs.json"), "w") as fh:
        json.dump(c2_reads, fh, indent=1)
    write_listing(B, c2_cases, c2_reads)
    c4 = {}
    for m in traj.MODELS:
        P = per[m]
        fails = P["runs"]["fail"]
        c4[m] = {k: dict(v) for k, v in P.items()}
        c4[m]["claims_success_but_failed_rate"] = round(P["runs_with_false_claim"]["fail"] / fails, 4) if fails else None
        c4[m]["claims_by_status"] = dict(claims_status[m])
    rep["C4"] = c4
    # ---------------------------------------------------------------- C0, C1, C3
    rep["C0"] = traj.load_json(os.path.join(B, "reports/c0.json"))
    c1 = traj.load_json(os.path.join(B, "reports/c1.json"))
    rep["C1"] = {"plants": c1["plants"], "passed": c1["passed"], "pass": c1["passed"] == c1["plants"]}
    c3p = os.path.join(B, "reports/c3.json")
    if os.path.exists(c3p):
        rep["C3"] = traj.load_json(c3p)
    c5p = os.path.join(B, "reports/c5.json")
    if os.path.exists(c5p):
        rep["C5"] = traj.load_json(c5p)
    with open(os.path.join(B, "reports/summary.json"), "w") as fh:
        json.dump(rep, fh, indent=1, sort_keys=True)
    print(json.dumps({"C2": rep["C2"]}, indent=1))
    for m in traj.MODELS:
        x = c4[m]
        print(m, "runs", x["runs"], "with refusal", x.get("runs_with_refusal"), "false-claim runs", x.get("runs_with_false_claim"),
              "rate", x["claims_success_but_failed_rate"], "only-key", x.get("failures_only_answer_key_sees"))


if __name__ == "__main__":
    main()
