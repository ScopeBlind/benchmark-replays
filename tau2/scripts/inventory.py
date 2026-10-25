"""Read-only inventory of the tau2-bench retail domain and its published runs.

Treats every input as untrusted data: parses JSON with the standard library,
prints counts, ids and model names only, never message text. Executes nothing
from the repository and replays no tool calls.

Usage:
  python3 -I inventory.py --domain <retail domain dir> --results <file> [--results <file> ...]
"""
import argparse
import json
import math
import os
import re
from collections import Counter, defaultdict

WRITE_TOOLS = {
    "cancel_pending_order",
    "exchange_delivered_order_items",
    "modify_pending_order_address",
    "modify_pending_order_items",
    "modify_pending_order_payment",
    "modify_user_address",
    "return_delivered_order_items",
}
MONEY_TOOLS = {
    "cancel_pending_order",
    "exchange_delivered_order_items",
    "modify_pending_order_items",
    "modify_pending_order_payment",
    "return_delivered_order_items",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def comb(n, k):
    return math.comb(n, k) if 0 <= k <= n else 0


def pass_hat_k(per_task_successes, n_trials, k):
    vals = [comb(c, k) / comb(n_trials, k) for c in per_task_successes.values()]
    return sum(vals) / len(vals) if vals else float("nan")


def actions_sig(task):
    ec = task.get("evaluation_criteria") or {}
    acts = ec.get("actions") or []
    return json.dumps([(a.get("name"), a.get("arguments")) for a in acts], sort_keys=True)


def domain_inventory(domain_dir):
    tasks = load(os.path.join(domain_dir, "tasks.json"))
    split = load(os.path.join(domain_dir, "split_tasks.json"))
    db = load(os.path.join(domain_dir, "db.json"))
    out = {}
    out["tasks"] = len(tasks)
    out["split_sizes"] = {k: len(v) for k, v in split.items()}
    rb = Counter()
    nl = 0
    nl_in_basis = 0
    comm = 0
    env_assert = 0
    init_state = 0
    gold_tool = Counter()
    tasks_with_write = 0
    tasks_with_money = 0
    tasks_no_write = 0
    gold_write_counts = Counter()
    for t in tasks:
        ec = t.get("evaluation_criteria") or {}
        basis = tuple(ec.get("reward_basis") or [])
        rb[basis] += 1
        if ec.get("nl_assertions"):
            nl += 1
            if "NL_ASSERTION" in basis:
                nl_in_basis += 1
        if ec.get("communicate_info"):
            comm += 1
        if ec.get("env_assertions"):
            env_assert += 1
        if t.get("initial_state"):
            init_state += 1
        names = [a.get("name") for a in (ec.get("actions") or [])]
        for n in names:
            gold_tool[n] += 1
        w = [n for n in names if n in WRITE_TOOLS]
        gold_write_counts[len(w)] += 1
        if w:
            tasks_with_write += 1
        else:
            tasks_no_write += 1
        if any(n in MONEY_TOOLS for n in names):
            tasks_with_money += 1
    out["reward_basis"] = {"+".join(k) or "(none)": v for k, v in rb.items()}
    out["tasks_with_nl_assertions"] = nl
    out["tasks_with_NL_ASSERTION_in_basis"] = nl_in_basis
    out["tasks_with_communicate_info"] = comm
    out["tasks_with_env_assertions"] = env_assert
    out["tasks_with_initial_state"] = init_state
    out["gold_action_tool_counts"] = dict(gold_tool.most_common())
    out["tasks_with_gold_write"] = tasks_with_write
    out["tasks_with_gold_money_write"] = tasks_with_money
    out["tasks_with_no_gold_write"] = tasks_no_write
    out["gold_write_calls_per_task"] = dict(sorted(gold_write_counts.items()))
    # Database shape
    out["db_top_keys"] = sorted(db.keys())
    out["db_products"] = len(db["products"])
    out["db_variants"] = sum(len(p["variants"]) for p in db["products"].values())
    out["db_variants_available"] = sum(1 for p in db["products"].values() for v in p["variants"].values() if v.get("available"))
    out["db_users"] = len(db["users"])
    out["db_orders"] = len(db["orders"])
    out["db_order_status"] = dict(Counter(o["status"] for o in db["orders"].values()).most_common())
    pm = Counter()
    users_multi_pm = 0
    gift_balances = []
    for u in db["users"].values():
        kinds = [m.get("source") for m in u["payment_methods"].values()]
        pm.update(kinds)
        if len(kinds) > 1:
            users_multi_pm += 1
        gift_balances += [m.get("balance") for m in u["payment_methods"].values() if m.get("source") == "gift_card"]
    out["db_payment_method_sources"] = dict(pm)
    out["db_users_with_more_than_one_method"] = users_multi_pm
    if gift_balances:
        gb = sorted(gift_balances)
        out["db_gift_card_balance_min_median_max"] = [gb[0], gb[len(gb) // 2], gb[-1]]
    ph = Counter(len(o["payment_history"]) for o in db["orders"].values())
    out["db_payment_history_lengths"] = dict(sorted(ph.items()))
    out["db_order_keys_union"] = sorted({k for o in db["orders"].values() for k in o.keys()})
    tx = Counter(p["transaction_type"] for o in db["orders"].values() for p in o["payment_history"])
    out["db_payment_transaction_types"] = dict(tx)
    return out, {t["id"]: t for t in tasks}


def results_inventory(path, current_tasks):
    data = load(path)
    info = data.get("info") or {}
    out = {"file": os.path.basename(path)}
    out["timestamp"] = data.get("timestamp")
    gc = info.get("git_commit")
    out["git_commit"] = gc if isinstance(gc, str) and HEX40.match(gc) else "(not a commit hash)"
    out["agent_llm"] = (info.get("agent_info") or {}).get("llm")
    out["agent_impl"] = (info.get("agent_info") or {}).get("implementation")
    out["user_llm"] = (info.get("user_info") or {}).get("llm")
    out["num_trials"] = info.get("num_trials")
    out["seed"] = info.get("seed")
    out["max_steps"] = info.get("max_steps")
    out["max_errors"] = info.get("max_errors")
    emb = {t["id"]: t for t in data.get("tasks") or []}
    out["embedded_tasks"] = len(emb)
    diff_actions = sorted((tid for tid in emb if tid in current_tasks and actions_sig(emb[tid]) != actions_sig(current_tasks[tid])), key=lambda x: int(x) if x.isdigit() else x)
    out["embedded_tasks_gold_actions_differ_from_current"] = len(diff_actions)
    out["embedded_tasks_gold_actions_differ_ids"] = diff_actions
    out["embedded_tasks_missing_from_current"] = sorted(set(emb) - set(current_tasks))
    out["current_tasks_missing_from_embedded"] = sorted(set(current_tasks) - set(emb))
    emb_rb = Counter("+".join((t.get("evaluation_criteria") or {}).get("reward_basis") or []) for t in emb.values())
    out["embedded_reward_basis"] = dict(emb_rb)
    sims = data.get("simulations") or []
    out["simulations"] = len(sims)
    out["termination_reasons"] = dict(Counter(s.get("termination_reason") for s in sims))
    rewards = Counter()
    dbm = Counter()
    per_task = defaultdict(int)
    trials = defaultdict(int)
    tool_calls = Counter()
    write_calls = Counter()
    tool_errors = 0
    write_errors = 0
    sims_with_write = 0
    sims_with_money = 0
    msgs = 0
    roles = Counter()
    tc_keys = set()
    tm_keys = set()
    for s in sims:
        ri = s.get("reward_info") or {}
        r = ri.get("reward")
        rewards[r] += 1
        dc = ri.get("db_check") or {}
        dbm[dc.get("db_match")] += 1
        tid = s.get("task_id")
        trials[tid] += 1
        if r == 1.0:
            per_task[tid] += 1
        else:
            per_task.setdefault(tid, 0)
        m = s.get("messages") or []
        msgs += len(m)
        pending = {}
        wrote = False
        money = False
        for msg in m:
            roles[msg.get("role")] += 1
            for tc in msg.get("tool_calls") or []:
                tc_keys.update(tc.keys())
                name = tc.get("name")
                tool_calls[name] += 1
                pending[tc.get("id")] = name
                if name in WRITE_TOOLS:
                    write_calls[name] += 1
                    wrote = True
                if name in MONEY_TOOLS:
                    money = True
            if msg.get("role") == "tool":
                tm_keys.update(msg.keys())
                if msg.get("error"):
                    tool_errors += 1
                    if pending.get(msg.get("id")) in WRITE_TOOLS:
                        write_errors += 1
        sims_with_write += wrote
        sims_with_money += money
    out["published_reward_values"] = {str(k): v for k, v in rewards.items()}
    out["published_db_match"] = {str(k): v for k, v in dbm.items()}
    out["tasks_in_sims"] = len(trials)
    out["trials_per_task"] = dict(Counter(trials.values()))
    n = out["num_trials"] or 4
    out["pass_hat_k_published"] = {f"k={k}": round(pass_hat_k(per_task, n, k), 4) for k in range(1, n + 1)}
    out["mean_messages_per_sim"] = round(msgs / len(sims), 1) if sims else 0
    out["message_roles"] = dict(roles)
    out["tool_call_keys"] = sorted(tc_keys)
    out["tool_message_keys"] = sorted(tm_keys)
    out["tool_calls_total"] = sum(tool_calls.values())
    out["tool_calls_by_name"] = dict(tool_calls.most_common())
    out["write_calls_by_name"] = dict(write_calls.most_common())
    out["tool_results_with_error"] = tool_errors
    out["write_results_with_error"] = write_errors
    out["sims_with_any_write"] = sims_with_write
    out["sims_with_money_write"] = sims_with_money
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--results", action="append", default=[])
    args = ap.parse_args()
    dom, current = domain_inventory(args.domain)
    print(json.dumps({"domain": dom}, indent=1, sort_keys=False))
    for p in args.results:
        print(json.dumps({"results": results_inventory(p, current)}, indent=1, sort_keys=False))


if __name__ == "__main__":
    main()
