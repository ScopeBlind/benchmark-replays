"""Step 2: run every gold write through the gate with the context it would have.

For each v1.0.1 task the gold actions are replayed on a fresh database. Before
each gold write the session is given what a careful agent would have seen:
the order's owner located, their profile, the order, and the products of its
items, all read from the gold replay's own state at that moment. A refusal is
a conflict between the written policy and the answer key; it is reported, not
fixed. Gold writes that also fail in tau2 are marked.

Usage: python3 -I gold_check.py --out gold_check.json [--gateway <dir>] [--data <dir>] [--base <dir>]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_builder as C  # noqa: E402
import evidence as E  # noqa: E402
import replay as RP  # noqa: E402
import retail_env as R  # noqa: E402
import traj  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    RP.add_path_args(ap)
    a = ap.parse_args()
    RP.set_paths(a)
    base = R.load_db(os.path.join(RP.DATA, "domains/retail/db.json"))
    base_json = json.dumps(base)
    pdir = os.path.join(RP.BASE, "policy/tau2-retail-v1")
    gate = RP.Helper(os.path.join(RP.BASE, "keys/gate.json"), os.path.join(RP.BASE, "logs/helper-gold.log"))
    rows, refused = [], []
    for t in traj.load_json(os.path.join(RP.DATA, "domains/retail/tasks.json")):
        env = R.Env(json.loads(base_json))
        s = C.Session()
        for idx, act in enumerate((t.get("evaluation_criteria") or {}).get("actions") or []):
            tool, args = act["name"], act.get("arguments") or {}
            if tool not in R.WRITE_TOOLS:
                continue
            owner = args.get("user_id") if tool == "modify_user_address" else (env.db["orders"].get(args.get("order_id")) or {}).get("user_id")
            if owner:
                s.observe("find_user_id_by_email", {}, owner, False)
                s.observe("get_user_details", {"user_id": owner}, json.dumps(env.db["users"][owner]), False)
            oid = args.get("order_id")
            if oid in env.db["orders"]:
                order = env.db["orders"][oid]
                s.observe("get_order_details", {"order_id": oid}, json.dumps(order), False)
                for it in order["items"]:
                    if it["product_id"] in env.db["products"]:
                        s.observe("get_product_details", {"product_id": it["product_id"]}, json.dumps(env.db["products"][it["product_id"]]), False)
            facts = s.facts(tool, args)
            ev = gate.req({"op": "evaluate", "policy_dir": pdir, "tool": tool, "input": {"args": args, "session": facts}})
            content, err = env.call(tool, args)
            s.after_decision(tool)
            s.observe(tool, args, content, err)
            row = {"task": t["id"], "action": idx, "tool": tool, "order_or_user": oid or args.get("user_id"),
                   "allowed": ev["allowed"], "rules": E.rule_ids(ev["reason"]) if not ev["allowed"] else [],
                   "fails_in_tau2_too": err, "tool_error": content if err else None}
            rows.append(row)
            if not ev["allowed"]:
                refused.append(row)
    gate.close()
    out = {"gold_writes": len(rows), "refused": len(refused), "refused_rows": refused,
           "refused_and_failing_in_tau2": sum(1 for r in refused if r["fails_in_tau2_too"]),
           "failing_in_tau2": [r for r in rows if r["fails_in_tau2_too"]]}
    with open(a.out, "w") as fh:
        json.dump({**out, "rows": rows}, fh, indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
