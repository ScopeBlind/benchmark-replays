"""Compute the answer key: the gold database hash for every task.

v1.0.1 base tasks (data/tau2/domains/retail/tasks.json, blob e95a9f89) and the
June 2025 tasks embedded in each result file. Gold actions are replayed on a
fresh database with the reference environment; a gold action that fails is
skipped, as tau2 does. For diffs, the key also stores the gold records of the
entities the gold actions changed.

Usage: python3 -I answer_key.py --db db.json --tasks tasks.json --results <file> [...] --out answer_key.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import retail_env as R  # noqa: E402
import traj  # noqa: E402


def gold_entry(base, actions):
    env, failed = R.gold_env(base, actions)
    delta = {}
    for coll in ("orders", "users", "products"):
        for k, v in env.db[coll].items():
            if base[coll].get(k) != v:
                delta.setdefault(coll, {})[k] = v
    return {"hash": env.hash(), "failed_gold_actions": failed, "delta": delta}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--tasks", required=True)
    ap.add_argument("--results", action="append", default=[])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    base = R.load_db(a.db)
    out = {"initial_db_hash": R.db_hash(base), "v101": {}, "embedded": {}, "communicate_info": {}}
    for t in traj.load_json(a.tasks):
        ec = t.get("evaluation_criteria") or {}
        out["v101"][t["id"]] = gold_entry(base, ec.get("actions"))
        out["communicate_info"][t["id"]] = ec.get("communicate_info") or []
    cache = {}
    for path in a.results:
        data = traj.load_json(path)
        m = traj.model_of(path)
        out["embedded"][m] = {}
        for t in data["tasks"]:
            acts = (t.get("evaluation_criteria") or {}).get("actions")
            key = json.dumps([(x.get("name"), x.get("arguments")) for x in acts or []], sort_keys=True)
            if key not in cache:
                cache[key] = gold_entry(base, acts)["hash"]
            out["embedded"][m][t["id"]] = cache[key]
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, sort_keys=True)
    n_failed = sum(1 for v in out["v101"].values() if v["failed_gold_actions"])
    print(f"v1.0.1 tasks: {len(out['v101'])}; tasks with a failing gold action: {n_failed}; "
          f"embedded sets: {len(out['embedded'])}; distinct embedded gold lists: {len(cache)}")


if __name__ == "__main__":
    main()
