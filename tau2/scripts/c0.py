"""C0 reproduction: database-only labels and per-call results, recorded world, no gate.

Replays every published run the way tau2's evaluator does (writes re-executed,
unknown tools skipped), and also executes reads at their place in the run so
every replayed result can be compared with the recorded one (calculate is
never evaluated). Compares the labels with (a) the published db_match under
each file's embedded June 2025 tasks, (b) the 16 Oct regrade under the v1.0.1
tasks, and (c) tau2's own predicted hashes from the cross-check, when given.

Usage: python3 -I c0.py [--labels labels.jsonl] [--tau2 crosscheck.json] --out c0.json
         [--data <tau2-bench data/tau2 dir>] [--base <experiment dir>]
Without --labels the comparison with the 16 Oct regrade (b) is skipped.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import retail_env as R  # noqa: E402
import traj  # noqa: E402

DATA = "upstream/tau2-bench/data/tau2"  # default for --data, relative to the working directory
BASE = "out/tau2"  # default for --base


def main():
    global DATA, BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels")
    ap.add_argument("--tau2")
    ap.add_argument("--out", required=True)
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--base", default=BASE)
    a = ap.parse_args()
    DATA, BASE = a.data, a.base
    key = traj.load_json(os.path.join(BASE, "frozen/answer_key.json"))
    base_json = json.dumps(R.load_db(os.path.join(DATA, "domains/retail/db.json")))
    labels = {}
    if a.labels:
        with open(a.labels) as fh:
            for line in fh:
                r = json.loads(line)
                if r.get("domain") == "retail":
                    labels[r["sim_id"]] = r
    t2 = traj.load_json(a.tau2) if a.tau2 else None
    per_model = defaultdict(Counter)
    mism_examples = []
    mism_by_tool = Counter()
    disagree = []
    hashes = {}
    files = sorted(f for f in os.listdir(os.path.join(DATA, "results/final")) if "_retail_" in f and f.endswith(".json"))
    for f in files:
        data = traj.load_json(os.path.join(DATA, "results/final", f))
        m = traj.model_of(f)
        for s in data["simulations"]:
            env = R.Env(json.loads(base_json))
            n_bad = 0
            for st in traj.extract_steps(s["messages"]):
                tool = st["tool"]
                if tool not in R.ALL_TOOLS or tool == "calculate" or st["result_index"] is None:
                    continue
                c, e = env.call(tool, st["args"])
                if R.parse_content(c) != R.parse_content(st["rec_content"]) or e != st["rec_error"]:
                    n_bad += 1
                    mism_by_tool[(tool, "error" if (e or st["rec_error"]) else "content")] += 1
                    if len(mism_examples) < 25:
                        mism_examples.append({"sim": s["id"][:8], "model": m, "task": s["task_id"], "call": st["i"], "tool": tool,
                                              "replayed_error": e, "recorded_error": st["rec_error"],
                                              "replayed": (c[:160] if e or st["rec_error"] else None),
                                              "recorded": (st["rec_content"][:160] if (e or st["rec_error"]) and st["rec_content"] else None)})
            h = env.hash()
            hashes[s["id"]] = h
            pub = ((s.get("reward_info") or {}).get("db_check") or {}).get("db_match")
            emb = key["embedded"][m][s["task_id"]]
            v101 = key["v101"][s["task_id"]]["hash"]
            lab = labels.get(s["id"])
            pm = per_model[m]
            pm["runs"] += 1
            pm["calls_with_result_mismatch"] += n_bad
            pm["runs_with_result_mismatch"] += int(n_bad > 0)
            pm["embedded_label_pass"] += int(h == emb)
            pm["published_db_match_true"] += int(pub is True)
            pm["agree_published_db_match"] += int((h == emb) == bool(pub))
            pm["v101_label_pass"] += int(h == v101)
            if lab is not None:
                pm["agree_16oct_regrade"] += int((h == v101) == (lab["env_reward"] == 1.0))
                pm["have_16oct_label"] += 1
            if t2 is not None:
                pm["agree_tau2_hash"] += int(t2["sims"].get(s["id"]) == h)
            if (h == emb) != bool(pub) or (lab is not None and (h == v101) != (lab["env_reward"] == 1.0)) or \
                    (t2 is not None and t2["sims"].get(s["id"]) != h):
                disagree.append({"sim": s["id"], "model": m, "task": s["task_id"], "trial": s["trial"], "ours_embedded": h == emb,
                                 "published_db_match": pub, "ours_v101": h == v101,
                                 "regrade_16oct": None if lab is None else lab["env_reward"] == 1.0,
                                 "tau2_hash_equal": None if t2 is None else t2["sims"].get(s["id"]) == h})
        del data
    out = {"per_model": {m: dict(c) for m, c in per_model.items()},
           "totals": dict(sum((Counter(c) for c in per_model.values()), Counter())),
           "result_mismatch_by_tool": {f"{k[0]}/{k[1]}": v for k, v in mism_by_tool.most_common()},
           "mismatch_examples": mism_examples, "disagreements": disagree,
           "tau2_errors": (t2 or {}).get("errors"), "tau2_network_attempts": (t2 or {}).get("network_attempts")}
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    with open(os.path.join(os.path.dirname(a.out), "recorded_hashes.json"), "w") as fh:
        json.dump(hashes, fh)
    print(json.dumps({"totals": out["totals"], "disagreements": len(disagree), "result_mismatch_by_tool": out["result_mismatch_by_tool"]}, indent=1))


if __name__ == "__main__":
    main()
