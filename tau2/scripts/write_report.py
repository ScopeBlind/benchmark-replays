"""Write reports/report.md from the step outputs (plain ASCII, no em or en dashes).

Usage: python3 -I write_report.py [--base <experiment dir>]
"""
import argparse
import json
import os
import sys

B = "out/tau2"  # default for --base, relative to the working directory
R = os.path.join(B, "reports")


def load(name):
    p = os.path.join(R, name)
    return json.load(open(p)) if os.path.exists(p) else None


def main():
    global B, R
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=B)
    B = ap.parse_args().base
    R = os.path.join(B, "reports")
    s = load("summary.json")
    c0, c1, c3, c5, gold = load("c0.json"), load("c1.json"), load("c3.json"), load("c5.json"), load("gold_check.json")
    out = ["# tau2 retail replay: results (steps 0 to 6)", "",
           "Policy tau2-retail-v1 (sha256:a867d85e...), protect-mcp 0.32.2 in library mode with a 2% CLI cross-check,",
           "verifier @veritasacta/verify 0.11.0 (signatures and links only). Answer key: database only, v1.0.1 base tasks.",
           "Registration v1 signed before step 1; one pre-registered substitution (claude P2c) signed as an addendum.", ""]
    t = c0["totals"]
    out += ["## C0 reproduction", "",
            f"- Runs {t['runs']}; agree with published db_match {t['agree_published_db_match']} (passes {t['embedded_label_pass']});",
            f"  agree with the 16 Oct regrade {t['agree_16oct_regrade']} (passes {t['v101_label_pass']}); per-call result mismatches 0.",
            f"- tau2's own code: recorded hashes equal {c0['tau2_crosscheck']['recorded_hash_equal']} of {c0['tau2_crosscheck']['runs']}, "
            f"embedded gold {c0['tau2_crosscheck']['embedded_gold_equal']} of {c0['tau2_crosscheck']['embedded_gold_n']}, "
            f"v1.0.1 gold {c0['tau2_crosscheck']['v101_gold_equal']} of 114; network attempts {c0['tau2_crosscheck']['network_attempts']}.", "",
            "## Step 2 gold consistency", "",
            f"- Gold writes {gold['gold_writes']}, refused {gold['refused']}, all of which also fail inside tau2 ({gold['refused_and_failing_in_tau2']}).", ""]
    out += ["## C1 planted failures", "", f"- {c1['passed']} of {c1['plants']} plants produce the outcome written before the run.", ""]
    out += ["| Plant | Model | Task | Pass | Key result |", "|---|---|---|---|---|"]
    for x in c1["rows"]:
        c = x["checks"]
        key = []
        if c.get("refusals", {}).get("got"):
            key.append("refused: " + "; ".join(",".join(r[1]) for r in c["refusals"]["got"]))
        if "diff" in c:
            key.append("diff: " + ("none" if not c["diff"]["got"] else "; ".join(f"{k} {v}" for k, v in c["diff"]["got"].items())))
        if "e5" in c:
            key.append(f"E5 {c['e5']['got'].get('result')} executed {c['e5']['got'].get('executed')} stated {c['e5']['got'].get('stated')}")
        if "e6_reported" in c:
            key.append(f"E6 {c['e6_reported'].get('result')}")
        if "reexecution_under_pinned" in c:
            key.append(f"policy digest changes at call {c['policy_change']['first_receipt_with_other_digest_call']}; flips {len(c['reexecution_under_pinned']['flips'])}")
        if "verify_exit" in c:
            key.append(f"verify exit {c['verify_exit']} ({c['verify_outcome']}); summary binds count {c['summary_count_matches']} head {c['summary_head_matches']}")
        out.append(f"| {x['plant']} | {x['model'][:22]} | {x['task']} | {'yes' if x['pass'] else 'NO'} | {' / '.join(key)} |")
    c2 = s["C2"]
    out += ["", "## C2 no honest passing run blocked", "",
            f"- Passing published runs {c2['passing_published_runs']}; controls {c2['controls']} with {c2['control_refused_writes']} refused writes.",
            f"- Strict count: {c2['strict_refused_writes_in_passing_runs']} refused writes in {c2['strict_runs_with_refused_write']} passing runs.",
            f"- Mechanical split: {c2['split']}; ungrounded {c2['ungrounded']}. Refused reads in passing runs {c2['refused_reads_in_passing_runs']} {c2['refused_reads_split']}.",
            "- Full listing: reports/c2_listing.txt (rule, policy line, quote, evidence, recorded tool result).", ""]
    if c3:
        out += ["## C3 offline verification", ""]
        for k, v in c3["runs"].items():
            out.append(f"- {k}: runs {v['runs']}, problem runs {v['problem_runs']}, decisions {v['calls']}, re-executed under own policy {v['reexec_own_ok']}, flips under pinned v1 {v['reexec_pinned_flips']}")
        for k, v in c3["verify"].items():
            out.append(f"- verify {k}: {json.dumps(v)[:600]}")
        out.append(f"- CLI cross-check: {json.dumps(c3['cli'])[:600]}")
        out.append(f"- Tamper set: {json.dumps(c3['tamper'])[:1500]}")
        out.append("")
    out += ["## C4 description per model (database-only key; transcript checks are unaudited heuristics)", ""]
    for m, x in s["C4"].items():
        out.append(f"- {m}: runs {x['runs']}; runs with a refusal {x.get('runs_with_refusal')}; "
                   f"claims-success-but-failed (unaudited pattern count) {x['claims_success_but_failed_rate']}; "
                   f"failures with no refusal {x.get('failures_without_refusal')}; failures only the answer key sees {x.get('failures_only_answer_key_sees')}")
    if c5:
        out += ["", "## C5 stability", "", f"- {c5['identical']} of {c5['compared']} runs identical: {c5['by_set']}"]
    txt = "\n".join(out) + "\n"
    txt = txt.replace("\u2014", "-").replace("\u2013", "-")
    open(os.path.join(R, "report.md"), "w").write(txt)
    print("wrote", os.path.join(R, "report.md"), len(txt))


if __name__ == "__main__":
    main()
