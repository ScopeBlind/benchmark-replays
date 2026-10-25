"""Replay tau2 retail runs through protect-mcp in library mode.

For every run, two worlds:
  recorded: every write executed as tau2's evaluator replays it (no gate); this
            gives the database-only label (C0);
  enforced: each call goes to the gate first; a refused call does not run and
            produces no observation; facts for the next decision come only from
            results of calls that ran.
Per call the gate signs a decision receipt over {args, session}; per executed
call it signs an observation receipt over the result's digest. The harness
key signs a read-back of every entity a write touched and a run summary that
binds the gate chain's length and head.

Usage:
  python3 -I replay.py --set published|planted|controls --out <dir> --tag pass1
         [--worker K --workers N] [--sample FRACTION --seed S] [--plants plants-v2.json]
         [--gateway <protect-mcp dir>] [--data <tau2-bench data/tau2 dir>] [--base <experiment dir>]
Path defaults are relative to the working directory (see add_path_args).
"""
import argparse
import copy
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_builder as C  # noqa: E402
import evidence as E  # noqa: E402
import retail_env as R  # noqa: E402
import traj  # noqa: E402

# Paths. The defaults are relative to the working directory; every entry point
# takes --gateway, --data and --base (add_path_args) and calls set_paths.
GATEWAY = "tools/protect-mcp"  # protect-mcp 0.32.2 checkout, dist/ built, node_modules/ installed
HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate_helper.mjs")
DATA = "upstream/tau2-bench/data/tau2"  # tau2-bench data/tau2 at commit 0c69df45, read as data only
BASE = "out/tau2"  # experiment directory: keys/, policy/, frozen/, runs/, reports/, logs/
MIN_FREE = int(1.5 * 1024 ** 3)


def add_path_args(ap):
    ap.add_argument("--gateway", default=GATEWAY, help="protect-mcp 0.32.2 directory (dist/ and node_modules/)")
    ap.add_argument("--data", default=DATA, help="tau2-bench data/tau2 directory at commit 0c69df45")
    ap.add_argument("--base", default=BASE, help="experiment directory (keys/, policy/, frozen/, runs/, reports/, logs/)")


def set_paths(a):
    global GATEWAY, DATA, BASE
    GATEWAY, DATA, BASE = a.gateway, a.data, a.base


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Helper:
    def __init__(self, key, log):
        self.log = open(log, "a")
        self.p = subprocess.Popen(["node", HELPER, "--gateway", GATEWAY, "--key", key], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.log, text=True, bufsize=1)

    def req(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("gate helper stopped")
        r = json.loads(line)
        if not r.get("ok"):
            raise RuntimeError("gate helper error: " + str(r.get("error")))
        return r

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()
        self.log.close()


class Chain:
    def __init__(self, path, helper):
        self.path, self.helper, self.prev, self.count = path, helper, None, 0
        self.fh = open(path, "w") if path else None

    def add(self, reply):
        if self.fh:
            self.fh.write(reply["receipt"] + "\n")
        self.prev = reply["link"]
        self.count += 1
        return reply

    def decide(self, policy_dir, tool, gate_input):
        return self.add(self.helper.req({"op": "decide", "policy_dir": policy_dir, "tool": tool, "input": gate_input, "prev": self.prev}))

    def observe(self, tool, obj):
        return self.add(self.helper.req({"op": "observe", "tool": tool, "input": obj, "prev": self.prev}))

    def close(self):
        if self.fh:
            self.fh.close()


class RecView:
    """The recorded world as the agent saw it before one call (for grounding)."""

    def __init__(self, sess, first_result, transfer_index):
        self.s = sess
        self.first_result = dict(first_result)
        self.transfer_index = transfer_index

    def read_of_order(self, oid):
        return self.first_result.get(oid) if isinstance(oid, str) else None

    def located_user(self):
        return self.s.auth_user

    def order(self, oid):
        return self.s.orders.get(oid) if isinstance(oid, str) else None

    def method(self, pmid):
        return self.s.methods.get(pmid) if isinstance(pmid, str) else None

    def product(self, pid):
        return self.s.products.get(pid) if isinstance(pid, str) else None

    def item_changes(self, oid):
        return self.s.item_changes.get(oid, 0) if isinstance(oid, str) else 0

    def transferred(self):
        return self.transfer_index


def touched(db, tool, args):
    """Entities a write can change: its order and that order's user, or the user."""
    a = args if isinstance(args, dict) else {}
    out = []
    if tool == "modify_user_address":
        if isinstance(a.get("user_id"), str) and a["user_id"] in db["users"]:
            out.append(("users", a["user_id"]))
    else:
        oid = a.get("order_id")
        if isinstance(oid, str) and oid in db["orders"]:
            out.append(("orders", oid))
            uid = db["orders"][oid].get("user_id")
            if uid in db["users"]:
                out.append(("users", uid))
    return out


def effect(before, db, ents):
    out = []
    for coll, k in ents:
        b, a = before.get((coll, k)), db[coll].get(k)
        if b != a:
            out.append({"collection": coll, "id": k, "fields": sorted({p.split("[")[0] for p in R.diff_paths(b, a)} - {""})})
    return out


def entity_diff(db, base, gold_delta):
    """(collection, id) -> sorted fields where db differs from gold, over entities changed in either."""
    out = {}
    for coll in ("orders", "users", "products"):
        gd = gold_delta.get(coll, {})
        keys = set(gd)
        for k, v in db[coll].items():
            if base[coll].get(k) != v:
                keys.add(k)
        for k in sorted(keys):
            g = gd.get(k, base[coll].get(k))
            f = db[coll].get(k)
            if f != g:
                fields = sorted({p.split("[")[0] for p in R.diff_paths(f, g)} - {""})
                out[f"{coll}/{k}"] = fields
    return out


def entity_matches(db, base, gold_delta, ent):
    coll, k = ent
    g = gold_delta.get(coll, {}).get(k, base[coll].get(k))
    return db[coll].get(k) == g


def run_one(spec, ctx, gate, harness, write_files=True):
    msgs = spec["messages"]
    steps = traj.extract_steps(msgs)
    rid = spec["run_id"]
    odir = os.path.join(ctx["out"], rid)
    if write_files:
        os.makedirs(odir, exist_ok=True)
    gchain = Chain(os.path.join(odir, "gate.jsonl") if write_files else None, gate)
    hchain = Chain(os.path.join(odir, "harness.jsonl") if write_files else None, harness)
    base = ctx["base"]
    renv = R.Env(json.loads(ctx["base_json"]))
    genv = R.Env(json.loads(ctx["base_json"]))
    gs = C.Session(spec.get("approval_mode"), spec.get("approvals"))
    rs = C.Session(spec.get("approval_mode"), spec.get("approvals"))
    first_result, transfer_index = {}, None
    sched = spec.get("schedule") or {}
    swap_step = None
    if sched:
        swap_step = next(s["i"] for s in steps if s["call_id"] == sched["swap_after_call_id"])
    calls, refusals, divergences, rec_mismatch = [], [], [], []
    first_refusal = None
    policy_digests = set()
    for s in steps:
        tool, args = s["tool"], s["args"]
        label = sched["label"] if (swap_step is not None and s["i"] > swap_step) else "v1"
        pdir = ctx["policies"][label]
        # recorded world: tau2 replays every write, whatever the gate would say
        if tool in R.WRITE_TOOLS and s["result_index"] is not None:
            rc, re_ = renv.call(tool, args)
            if R.parse_content(rc) != R.parse_content(s["rec_content"]) or re_ != s["rec_error"]:
                rec_mismatch.append({"call": s["i"], "tool": tool, "replayed_error": re_, "recorded_error": s["rec_error"]})
        rec_facts = rs.facts(tool, args)
        facts = gs.facts(tool, args)
        gate_input = {"args": args, "session": facts}
        d = gchain.decide(pdir, tool, gate_input)
        policy_digests.add(d["policy_digest"])
        rec = {"i": s["i"], "msg_index": s["msg_index"], "call_id": s["call_id"], "tool": tool, "args": args, "session": facts,
               "gate_input_sha256": sha(C.jcs(gate_input)), "policy": label, "policy_digest": d["policy_digest"],
               "decision": d["decision"], "reason": d["reason"], "rules": E.rule_ids(d["reason"]) if d["decision"] == "deny" else [],
               "request_id": d["request_id"], "eval_error": d.get("error"), "executed": False}
        snap_profile = gs.profiles.get(gs.auth_user)
        if d["decision"] == "allow":
            if tool == "calculate":
                content, err, source = s["rec_content"] or "", bool(s["rec_error"]), "recorded"
            else:
                pre = {(c, k): copy.deepcopy(genv.db[c].get(k)) for c, k in touched(genv.db, tool, args)} if tool in R.WRITE_TOOLS else None
                content, err = genv.call(tool, args)
                source = "replay"
                if tool in R.WRITE_TOOLS:
                    rec["effect"] = effect(pre, genv.db, list(pre.keys()))
            gs.observe(tool, args, content, err)
            o = gchain.observe(f"{tool}.observed", {"request_id": d["request_id"], "result_sha256": sha(content), "error": err, "source": source})
            rec.update(executed=True, result_source=source, result_error=err, result_sha256=sha(content), result=content,
                       observation_request_id=o["request_id"],
                       matches_recorded=(R.parse_content(content) == R.parse_content(s["rec_content"]) and err == s["rec_error"]))
            if first_refusal is None and not rec["matches_recorded"] and source == "replay":
                divergences.append({"call": s["i"], "tool": tool, "replayed_error": err, "recorded_error": s["rec_error"]})
        else:
            ev = ctx["gate_eval"].req({"op": "evaluate", "policy_dir": pdir, "tool": tool, "input": {"args": args, "session": rec_facts}})
            rec["rec_session"] = rec_facts
            rec["under_recorded_facts"] = {"allowed": ev["allowed"], "rules": E.rule_ids(ev["reason"]) if not ev["allowed"] else []}
            view = RecView(copy.deepcopy(rs), first_result, transfer_index)
            g = []
            for rule in (rec["under_recorded_facts"]["rules"] or rec["rules"]):
                kind, ok, why = E.ground(rule, {**s, "rec_charge_cents": (rec_facts.get("call") or {}).get("charge_cents")}, view)
                line, quote = E.POLICY_LINES.get(rule, ("", ""))
                g.append({"rule": rule, "test": kind, "grounded": ok, "evidence": why, "policy_line": line, "quote": quote})
            rec["grounding"] = g
            rec["first_order"] = not ev["allowed"]
            refusals.append(rec)
            if first_refusal is None:
                first_refusal = s["i"]
        gs.after_decision(tool)
        rs.after_decision(tool)
        if s["rec_content"] is not None and tool != "calculate":
            rs.observe(tool, args, s["rec_content"], s["rec_error"])
            if not s["rec_error"]:
                if tool == "get_order_details" or tool in C.ORDER_WRITES:
                    oid = args.get("order_id") if isinstance(args, dict) else None
                    if isinstance(oid, str):
                        first_result.setdefault(oid, s["i"])
                if tool == "transfer_to_human_agents" and transfer_index is None:
                    transfer_index = s["i"]
        rec["profile_snapshot_methods"] = sorted((snap_profile or {}).get("payment_methods", {}).keys())
        calls.append(rec)

    # ------------------------------------------------------------- outcomes
    gold = ctx["key"]["v101"][spec["task_id"]]
    rhash, ghash = renv.hash(), genv.hash()
    emb = ctx["key"]["embedded"].get(spec["model"], {}).get(spec["task_id"])
    rdiff = entity_diff(renv.db, base, gold["delta"])
    gdiff = entity_diff(genv.db, base, gold["delta"])
    # harness read-backs of every entity an executed write touched (enforced world)
    ents = []
    for c in calls:
        if c["executed"] and c["tool"] in R.WRITE_TOOLS and not c.get("result_error"):
            for e in c.get("effect") or []:
                if (e["collection"], e["id"]) not in ents:
                    ents.append((e["collection"], e["id"]))
            for e in touched(genv.db, c["tool"], c["args"])[:1]:
                if e not in ents:
                    ents.append(e)
    hinputs = []
    for coll, k in ents:
        obj = {"run_id": rid, "entity": coll, "id": k, "record_sha256": R.record_hash(genv.db[coll][k]), "world": "enforced"}
        hchain.observe("harness.readback", obj)
        hinputs.append(obj)
    # evidence
    e1 = []
    for c in calls:
        if c["tool"] in R.WRITE_TOOLS and c["executed"] and not c.get("result_error"):
            res = R.parse_content(c["result"])
            coll, k = touched(genv.db, c["tool"], c["args"])[0] if touched(genv.db, c["tool"], c["args"]) else (None, None)
            final = genv.db[coll][k] if coll else None
            fields = {"cancel_pending_order": ["status", "cancel_reason", "payment_history"],
                      "return_delivered_order_items": ["status", "return_items", "return_payment_method_id"],
                      "exchange_delivered_order_items": ["status", "exchange_items", "exchange_new_items", "exchange_payment_method_id", "exchange_price_difference"],
                      "modify_pending_order_items": ["status", "items", "payment_history"],
                      "modify_pending_order_payment": ["payment_history"],
                      "modify_pending_order_address": ["address"], "modify_user_address": ["address"]}[c["tool"]]
            ok = isinstance(res, dict) and final is not None and all(final.get(f) == res.get(f) for f in fields)
            later = any(x["i"] > c["i"] and x["executed"] and x["tool"] in R.WRITE_TOOLS and not x.get("result_error")
                        and touched(genv.db, x["tool"], x["args"])[:1] == [(coll, k)] for x in calls)
            e1.append({"call": c["i"], "tool": c["tool"], "entity": f"{coll}/{k}", "status": "complete" if ok else ("superseded" if later else "missing")})
    e4, e5, e6, e10 = [], [], [], []
    for c, s in zip(calls, steps):
        if c["tool"] in R.WRITE_TOOLS:
            e4.append({"call": c["i"], **E.e4_confirmation(msgs, s)})
            e5.append({"call": c["i"], **E.e5_amount(msgs, s, c["session"])})
            e6.append({"call": c["i"], **E.e6_destination(msgs, s, _profile_at(gs, c))})
            if c["tool"] == "cancel_pending_order":
                e10.append({"call": c["i"], **E.e10_reason(msgs, s)})
    claims = E.e7_claims(msgs)
    w_enf = [{"tool": c["tool"], "entity": (touched(genv.db, c["tool"], c["args"]) or [(None, None)])[0], "executed": c["executed"],
              "error": bool(c.get("result_error")), "refused": c["decision"] == "deny"} for c in calls if c["tool"] in R.WRITE_TOOLS]
    w_rec = [{"tool": s["tool"], "entity": (touched(renv.db, s["tool"], s["args"]) or [(None, None)])[0], "executed": s["result_index"] is not None,
              "error": bool(_replayed_error(s, rec_mismatch, renv)), "refused": False} for s in steps if s["tool"] in R.WRITE_TOOLS]
    claims_enf = E.classify_claims(claims, w_enf, lambda ent: ent[0] is not None and entity_matches(genv.db, base, gold["delta"], ent))
    claims_rec = E.classify_claims(claims, w_rec, lambda ent: ent[0] is not None and entity_matches(renv.db, base, gold["delta"], ent))
    exec_steps = [{**s, "executed": c["executed"]} for s, c in zip(steps, calls)]
    findings = {
        "refusals": [{"call": r["i"], "call_id": r["call_id"], "tool": r["tool"], "rules": r["rules"], "first_order": r["first_order"],
                      "under_recorded_facts": r["under_recorded_facts"], "grounding": r["grounding"]} for r in refusals],
        "e1": e1,
        "e2": {"enforced": ghash == gold["hash"], "recorded": rhash == gold["hash"]},
        "e3": {"enforced": gdiff, "recorded": rdiff},
        "e4": e4, "e5": e5, "e6": e6,
        "e7": {"enforced": claims_enf, "recorded": claims_rec},
        "e8": E.e8_calls_at_a_time(msgs),
        "e9": E.e9_transfer(msgs, exec_steps),
        "e10": e10,
        "e11": E.e11_told(msgs, ctx["key"]["communicate_info"].get(spec["task_id"], [])),
        "e13": gs.flags,
        "recorded_replay_mismatches": rec_mismatch,
        "divergence_before_first_refusal": divergences,
    }
    fsha = sha(C.jcs(findings))
    summary = {"run_id": rid, "gate_receipts": gchain.count, "gate_head": gchain.prev, "harness_readbacks": len(hinputs),
               "enforced_db_hash": ghash, "recorded_db_hash": rhash, "gold_db_hash": gold["hash"],
               "accepted_enforced": ghash == gold["hash"], "accepted_recorded": rhash == gold["hash"],
               "findings_sha256": fsha, "policy_digests": sorted(policy_digests)}
    hchain.observe("harness.summary", summary)
    hinputs.append(summary)
    stable = sha(C.jcs({"calls": [{k: c.get(k) for k in ("i", "tool", "args", "session", "decision", "reason", "policy_digest",
                                                         "gate_input_sha256", "executed", "result_sha256", "result_error")} for c in calls],
                        "findings": findings, "hashes": [rhash, ghash]}))
    result = {"run_id": rid, "set": spec["set"], "plant": spec.get("plant"), "model": spec["model"], "task_id": spec["task_id"],
              "trial": spec["trial"], "sim_id": spec["sim_id"], "published": spec.get("published"),
              "recorded_db_hash": rhash, "enforced_db_hash": ghash, "gold_db_hash": gold["hash"], "embedded_gold_hash": emb,
              "recorded_matches_embedded": rhash == emb, "accepted_recorded": rhash == gold["hash"], "accepted_enforced": ghash == gold["hash"],
              "n_calls": len(calls), "n_writes": sum(1 for c in calls if c["tool"] in R.WRITE_TOOLS),
              "refusals": findings["refusals"], "e3_enforced": gdiff, "e3_recorded": rdiff,
              "claims_recorded": claims_rec, "claims_enforced": claims_enf, "e8": findings["e8"],
              "e4_not_established": sum(1 for x in e4 if x["result"] != "established"),
              "e5": [x for x in e5 if x["result"] in ("mismatch", "match")], "e6": [x for x in e6 if x["result"] in ("mismatch", "match")],
              "e10_not_established": sum(1 for x in e10 if x["result"] != "established"), "e13": gs.flags,
              "rec_mismatch": len(rec_mismatch), "divergences": len(divergences), "gate_receipts": gchain.count,
              "harness_receipts": hchain.count, "gate_head": gchain.prev, "policy_digests": sorted(policy_digests),
              "effects": {c["call_id"]: c.get("effect") for c in calls if c.get("effect") is not None},
              "decisions": {c["call_id"]: [c["decision"], c["rules"]] for c in calls},
              "stable_digest": stable, "findings_sha256": fsha}
    gchain.close()
    hchain.close()
    if write_files:
        with open(os.path.join(odir, "calls.jsonl"), "w") as fh:
            for c in calls:
                fh.write(json.dumps(c, sort_keys=True) + "\n")
        with open(os.path.join(odir, "harness_inputs.jsonl"), "w") as fh:
            for h in hinputs:
                fh.write(json.dumps(h, sort_keys=True) + "\n")
        card = {"run": {k: spec.get(k) for k in ("run_id", "set", "plant", "model", "task_id", "trial", "sim_id", "published")},
                "policy": {"digests": sorted(policy_digests), "policy_text_sha256": ctx["policy_text_sha256"]},
                "answer_key": {"tasks_blob": "e95a9f898b2d1f6568ea8faec78edc3767ce747d", "gold_db_hash": gold["hash"]},
                "summary": summary, "findings": findings}
        with open(os.path.join(odir, "card.json"), "w") as fh:
            json.dump(card, fh, sort_keys=True, indent=1)
        with open(os.path.join(odir, "card.txt"), "w") as fh:
            fh.write(card_text(spec, calls, findings, summary, ctx))
    return result


def _profile_at(gs, c):
    methods = {}
    for m in c["profile_snapshot_methods"]:
        prof = gs.profiles.get(gs.auth_user) or {}
        if m in (prof.get("payment_methods") or {}):
            methods[m] = prof["payment_methods"][m]
    return {"payment_methods": methods}


def _replayed_error(step, rec_mismatch, renv):
    # the recorded world's own error for a write is the recorded error unless the replay disagreed
    for m in rec_mismatch:
        if m["call"] == step["i"]:
            return m["replayed_error"]
    return step["rec_error"]


def card_text(spec, calls, f, summary, ctx):
    n = len(calls)
    auth = sum(1 for c in calls if c["decision"] == "allow")
    lines = [
        f"Run        {spec['run_id']} (task {spec['task_id']} trial {spec['trial']}, {spec['model']}, sim {spec['sim_id'][:8]})",
    ]
    if spec.get("plant"):
        lines.append(f"           PLANTED {spec['plant']}")
    lines.append(f"Policy     {', '.join(summary['policy_digests'])}")
    lines.append(f"Calls      {n} attempted, {auth} authorized, {n - auth} refused")
    for r in f["refusals"]:
        lines.append(f"Refused    call {r['call']} {r['tool']}: {', '.join(r['rules'])}" + ("" if r["first_order"] else " (follows an earlier refusal)"))
    for e in f["e1"]:
        lines.append(f"Write      call {e['call']} {e['tool']} {e['entity']}: observed complete: {e['status']}")
    acc = "yes" if summary["accepted_enforced"] else "NO"
    lines.append(f"Accepted   {acc} under enforcement (final database {'equals' if summary['accepted_enforced'] else 'differs from'} the answer key)")
    if f["e3"]["enforced"]:
        lines.append("           differs at " + "; ".join(f"{k} {v}" for k, v in sorted(f["e3"]["enforced"].items())))
    if summary["accepted_recorded"] != summary["accepted_enforced"]:
        lines.append(f"           as recorded: {'yes' if summary['accepted_recorded'] else 'no'} (the refused calls ran in the recording)")
    ne = [x for x in f["e4"] if x["result"] != "established"]
    for x in ne:
        lines.append(f"Not established  confirmation before call {x['call']}: {x.get('missing')}")
    for x in f["e5"]:
        if x["result"] == "mismatch":
            lines.append(f"Mismatch   amount at call {x['call']}: stated {x['stated']}, executed {x['executed']}")
    for x in f["e6"]:
        if x["result"] == "mismatch":
            lines.append(f"Mismatch   destination at call {x['call']}: proposal named {x['proposal_named']}, executed {x['executed']}")
    for c in f["e7"]["enforced"]:
        lines.append(f"Claim      \"{c['match']}\": {c['status']}")
    lines.append(f"Evidence   {summary['gate_receipts']} gate receipts, {summary['harness_readbacks'] + 1} harness receipts; "
                 "verify with @veritasacta/verify 0.11.0 --replay-chain and the pinned keys")
    return "\n".join(lines) + "\n"


def published_specs(sample=None, seed=0):
    files = sorted(f for f in os.listdir(os.path.join(DATA, "results/final")) if "_retail_" in f and f.endswith(".json"))
    chosen = None
    for f in files:
        data = traj.load_json(os.path.join(DATA, "results/final", f))
        m = traj.model_of(f)
        sims = data["simulations"]
        if sample is not None:
            rnd = random.Random(f"{seed}/{m}")
            k = max(1, int(round(len(sims) * sample)))
            chosen = set(s["id"] for s in rnd.sample(sims, k))
        for s in sims:
            if chosen is not None and s["id"] not in chosen:
                continue
            ri = s.get("reward_info") or {}
            yield {"run_id": f"published/{m}/{s['task_id']}_{s['trial']}", "set": "published", "model": m, "task_id": s["task_id"],
                   "trial": s["trial"], "sim_id": s["id"], "messages": s["messages"],
                   "published": {"reward": ri.get("reward"), "db_match": (ri.get("db_check") or {}).get("db_match")}}
        del data


def frozen_specs(kind, plants_file="plants.json"):
    p = traj.load_json(os.path.join(BASE, "frozen", plants_file))
    for x in (p["plants"] if kind == "planted" else p["controls"]):
        if x.get("post_hoc"):
            continue
        yield x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, choices=["published", "planted", "controls"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--worker", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--sample", type=float)
    ap.add_argument("--seed", type=int, default=20261025)
    ap.add_argument("--no-files", action="store_true")
    ap.add_argument("--plants", default="plants.json")
    ap.add_argument("--only", help="comma-separated run ids to run (others skipped)")
    add_path_args(ap)
    a = ap.parse_args()
    set_paths(a)
    os.makedirs(a.out, exist_ok=True)
    key = traj.load_json(os.path.join(BASE, "frozen/answer_key.json"))
    base = R.load_db(os.path.join(DATA, "domains/retail/db.json"))
    ctx = {"out": a.out, "key": key, "base": base, "base_json": json.dumps(base),
           "policies": {lbl: os.path.join(BASE, "policy", d) for lbl, d in
                        (("v1", "tau2-retail-v1"), ("p5a", "tau2-retail-v1-p5a"), ("p5b", "tau2-retail-v1-p5b"))},
           "policy_text_sha256": "2c9652afbce57d6e087768d37cda64d31c53d50b3e3225cfdb791bac66466467"}
    logs = os.path.join(BASE, "logs")
    os.makedirs(logs, exist_ok=True)
    gate = Helper(os.path.join(BASE, "keys/gate.json"), os.path.join(logs, f"helper-gate-{a.tag}-{a.set}-w{a.worker}.log"))
    harness = Helper(os.path.join(BASE, "keys/harness.json"), os.path.join(logs, f"helper-harness-{a.tag}-{a.set}-w{a.worker}.log"))
    ctx["gate_eval"] = gate
    specs = published_specs(a.sample, a.seed) if a.set == "published" else frozen_specs("planted" if a.set == "planted" else "controls", a.plants)
    only = set(a.only.split(",")) if a.only else None
    res_path = os.path.join(a.out, f"results-{a.set}-{a.tag}-w{a.worker}.jsonl")
    t0 = time.time()
    n = 0
    with open(res_path, "w") as out:
        for j, spec in enumerate(specs):
            if j % a.workers != a.worker:
                continue
            if only is not None and spec["run_id"] not in only:
                continue
            if n % 25 == 0 and shutil.disk_usage(a.out).free < MIN_FREE:
                print(json.dumps({"stop": "free disk below 1.5 GB", "free": shutil.disk_usage(a.out).free}), flush=True)
                sys.exit(7)
            r = run_one(spec, ctx, gate, harness, write_files=not a.no_files)
            out.write(json.dumps(r, sort_keys=True) + "\n")
            n += 1
    gate.close()
    harness.close()
    print(json.dumps({"set": a.set, "tag": a.tag, "worker": a.worker, "runs": n, "seconds": round(time.time() - t0, 1)}))


if __name__ == "__main__":
    main()
