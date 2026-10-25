"""Step 0: parse the policy with the gate and run the allow and deny vector table.

Every rule gets an allow case and a deny case; every session attribute of a
valid return and a valid exchange is also removed one at a time (the guard-absent
cases). Each vector runs through the protect-mcp CLI (`evaluate --cedar`, exit 0
allow, 2 deny) and through library mode; both must give the written result and
neither may report an evaluation error.

Usage: python3 -I vectors.py --policy <dir> --out vectors.json [--gateway <dir>] [--base <dir>]
"""
import argparse
import copy
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence as E  # noqa: E402
import replay as RP  # noqa: E402

CLI = None  # <gateway>/dist/cli.js, set in main() from --gateway
A = "retail."

RET_ARGS = {"order_id": "#W1", "item_ids": ["i1"], "payment_method_id": "credit_card_1"}
RET_SESSION = {"identities_located": 1, "auth_user": "u1",
               "order": {"user_id": "u1", "status": "delivered", "original_payment_method": "credit_card_1"},
               "payment_method": {"owner": "u1", "source": "credit_card"}, "prior_item_changes_on_order": 0,
               "call": {"digest": "sha256:aa", "missing_item_count": 0, "refund_cents": 1000}}
EXC_ARGS = {"order_id": "#W1", "item_ids": ["i1"], "new_item_ids": ["i2"], "payment_method_id": "credit_card_1"}
EXC_SESSION = {**copy.deepcopy(RET_SESSION), "call": {"digest": "sha256:bb", "same_item_count": 0, "products_checked": True,
                                                      "bad_new_item_count": 0, "missing_item_count": 0, "charge_cents": 0, "refund_cents": 500}}
CAN_ARGS = {"order_id": "#W1", "reason": "no longer needed"}
CAN_SESSION = {**copy.deepcopy(RET_SESSION), "order": {"user_id": "u1", "status": "pending", "original_payment_method": "credit_card_1"}}
PAY_ARGS = {"order_id": "#W1", "payment_method_id": "gift_card_1"}
PAY_SESSION = {**copy.deepcopy(CAN_SESSION), "payment_method": {"owner": "u1", "source": "gift_card", "balance_cents": 1500},
               "call": {"digest": "sha256:cc", "charge_cents": 1000, "refund_cents": 1000}}


def s(base, **patch):
    out = copy.deepcopy(base)
    for k, v in patch.items():
        cur = out
        parts = k.split("__")
        for p in parts[:-1]:
            cur = cur[p]
        if v is None:
            cur.pop(parts[-1], None)
        else:
            cur[parts[-1]] = v
    return out


def vectors():
    V = []
    add = lambda name, tool, args, sess, allow, rules=(): V.append(  # noqa: E731
        {"name": name, "tool": tool, "input": {"args": args, "session": sess}, "expect_allow": allow, "expect_rules": sorted(rules)})
    add("allowlist allow", "get_product_details", {"product_id": "p1"}, {}, True)
    add("allowlist deny", "delete_everything", {}, {}, False, ["default-deny"])
    add("auth deny", "get_order_details", {"order_id": "#W1"}, {"identities_located": 0}, False, [A + "identity.authenticate-first"])
    add("auth allow", "get_order_details", {"order_id": "#W1"}, {"identities_located": 1, "auth_user": "u1"}, True)
    add("profile other deny", "get_user_details", {"user_id": "u2"}, {"identities_located": 1, "auth_user": "u1"}, False, [A + "identity.other-customer-profile"])
    add("profile own allow", "get_user_details", {"user_id": "u1"}, {"identities_located": 1, "auth_user": "u1"}, True)
    add("order other deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, order__user_id="u2"), False, [A + "identity.other-customer-order"])
    add("return valid allow", "return_delivered_order_items", RET_ARGS, RET_SESSION, True)
    add("status unobserved deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, order=None), False, [A + "order.status-checked-first"])
    add("cancel delivered deny", "cancel_pending_order", CAN_ARGS, s(CAN_SESSION, order__status="delivered"), False, [A + "cancel.pending-only"])
    add("cancel pending allow", "cancel_pending_order", CAN_ARGS, CAN_SESSION, True)
    add("cancel reason deny", "cancel_pending_order", {**CAN_ARGS, "reason": "too expensive"}, CAN_SESSION, False, [A + "cancel.reason"])
    add("cancel reason allow", "cancel_pending_order", {**CAN_ARGS, "reason": "ordered by mistake"}, CAN_SESSION, True)
    addr = {"order_id": "#W1", "address1": "1 A St", "address2": "", "city": "X", "state": "CA", "country": "USA", "zip": "12345"}
    add("modify after item change deny", "modify_pending_order_address", addr, s(CAN_SESSION, order__status="pending (item modified)"), False, [A + "modify.pending-only"])
    add("modify pending allow", "modify_pending_order_address", addr, CAN_SESSION, True)
    add("return pending deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, order__status="pending"), False, [A + "return-exchange.delivered-only"])
    add("exchange once deny", "exchange_delivered_order_items", EXC_ARGS, s(EXC_SESSION, prior_item_changes_on_order=1), False, [A + "items.once-per-order"])
    add("exchange valid allow", "exchange_delivered_order_items", EXC_ARGS, EXC_SESSION, True)
    add("same option deny", "exchange_delivered_order_items", EXC_ARGS, s(EXC_SESSION, call__same_item_count=1), False, [A + "items.different-option"])
    add("unavailable deny", "exchange_delivered_order_items", EXC_ARGS, s(EXC_SESSION, call__bad_new_item_count=1), False, [A + "items.available-same-product"])
    add("not in order deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, call__missing_item_count=1), False, [A + "items.in-order"])
    add("refund to other card deny", "return_delivered_order_items", {**RET_ARGS, "payment_method_id": "credit_card_9"},
        RET_SESSION, False, [A + "return.refund-destination"])
    add("refund to own gift card allow", "return_delivered_order_items", {**RET_ARGS, "payment_method_id": "gift_card_1"},
        s(RET_SESSION, payment_method={"owner": "u1", "source": "gift_card", "balance_cents": 0}), True)
    add("unknown method deny", "exchange_delivered_order_items", {**EXC_ARGS, "payment_method_id": "paypal_9"},
        s(EXC_SESSION, payment_method=None), False, [A + "payment.customer-method"])
    add("other customer's method deny", "exchange_delivered_order_items", {**EXC_ARGS, "payment_method_id": "paypal_9"},
        s(EXC_SESSION, payment_method={"owner": "u2", "source": "paypal"}), False, [A + "payment.customer-method"])
    add("own method allow", "exchange_delivered_order_items", {**EXC_ARGS, "payment_method_id": "paypal_1"},
        s(EXC_SESSION, payment_method={"owner": "u1", "source": "paypal"}), True)
    add("gift card short deny", "modify_pending_order_payment", PAY_ARGS, s(PAY_SESSION, payment_method__balance_cents=500), False, [A + "payment.gift-card-balance"])
    add("gift card covers allow", "modify_pending_order_payment", PAY_ARGS, PAY_SESSION, True)
    add("payment same deny", "modify_pending_order_payment", {**PAY_ARGS, "payment_method_id": "credit_card_1"},
        s(PAY_SESSION, payment_method={"owner": "u1", "source": "credit_card"}), False, [A + "payment.change-must-differ"])
    add("after transfer deny", "get_product_details", {"product_id": "p1"}, {"transferred": True}, False, [A + "transfer.final"])
    add("approval mismatch deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, approval={"call_digest": "sha256:zz"}),
        False, [A + "approval.exact-call"])
    add("approval match allow", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, approval={"call_digest": "sha256:aa"}, approval_mode="required"), True)
    add("approval required deny", "return_delivered_order_items", RET_ARGS, s(RET_SESSION, approval_mode="required"), False, [A + "approval.required"])
    # guard-absent cases on a valid return, a valid exchange and a valid payment change
    for name, tool, args, sess in (("return", "return_delivered_order_items", RET_ARGS, RET_SESSION),
                                   ("exchange", "exchange_delivered_order_items", EXC_ARGS, EXC_SESSION),
                                   ("payment", "modify_pending_order_payment", PAY_ARGS, PAY_SESSION)):
        not_original = args["payment_method_id"] != sess["order"]["original_payment_method"]
        for k in list(sess.keys()):
            exp = {"auth_user": [A + "identity.authenticate-first"], "order": [A + "order.status-checked-first"]}.get(k, [])
            # a method other than the original needs its owner established as the located customer
            if not_original and k in ("auth_user", "payment_method"):
                exp = sorted(exp + [A + "payment.customer-method"])
            add(f"{name} without session.{k}", tool, args, s(sess, **{k: None}), not exp, exp)
            if isinstance(sess[k], dict):
                for kk in sess[k]:
                    exp2 = [A + "order.status-checked-first"] if (k, kk) == ("order", "status") else []
                    if (k, kk) == ("payment_method", "owner") and args["payment_method_id"] != sess["order"]["original_payment_method"]:
                        exp2 = [A + "payment.customer-method"]
                    add(f"{name} without session.{k}.{kk}", tool, args, s(sess, **{f"{k}__{kk}": None}), not exp2, exp2)
        add(f"{name} without session", tool, args, None, False,
            [A + "identity.authenticate-first", A + "order.status-checked-first", A + "payment.customer-method"])
    return V


def cli_eval(policy, tool, inp):
    p = subprocess.run(["node", CLI, "evaluate", "--cedar", policy, "--tool", tool, "--input", json.dumps(inp)],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    first = next((l for l in p.stdout.splitlines() if l.strip().startswith("{")), "{}")
    j = json.loads(first)
    return p.returncode, j


def main():
    global CLI
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--out", required=True)
    RP.add_path_args(ap)
    a = ap.parse_args()
    RP.set_paths(a)
    CLI = os.path.join(RP.GATEWAY, "dist/cli.js")
    lib = RP.Helper(os.path.join(RP.BASE, "keys/gate.json"), os.path.join(RP.BASE, "logs/helper-vectors.log"))
    parse = lib.req({"op": "parse", "policy_dir": a.policy})
    rows, bad = [], 0
    for v in vectors():
        inp = v["input"] if v["input"]["session"] is not None else {"args": v["input"]["args"]}
        code, cj = cli_eval(a.policy, v["tool"], inp)
        lj = lib.req({"op": "evaluate", "policy_dir": a.policy, "tool": v["tool"], "input": inp})
        cli_allow = code == 0
        rules_cli = sorted(E.rule_ids(cj.get("reason"))) if not cli_allow else []
        rules_lib = sorted(E.rule_ids(lj.get("reason"))) if not lj["allowed"] else []
        err = any(x in (str(cj.get("reason")) + str(lj.get("reason"))) for x in ("errored", "eval_error", "unparseable", "not_available"))
        ok = (cli_allow == v["expect_allow"] and lj["allowed"] == v["expect_allow"] and rules_cli == v["expect_rules"]
              and rules_lib == v["expect_rules"] and not err and code in (0, 2))
        bad += not ok
        rows.append({"name": v["name"], "tool": v["tool"], "expect_allow": v["expect_allow"], "expect_rules": v["expect_rules"],
                     "cli_exit": code, "cli_rules": rules_cli, "lib_allowed": lj["allowed"], "lib_rules": rules_lib,
                     "evaluation_error": err, "ok": ok})
    lib.close()
    res = {"parse": parse, "policy_digest": cj.get("policy_digest"), "vectors": len(rows), "failed": bad, "rows": rows}
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps({"parse_ok": parse.get("parse_ok"), "vectors": len(rows), "failed": bad, "policy_digest": res["policy_digest"]}))
    for r in rows:
        if not r["ok"]:
            print("FAIL", json.dumps(r))


if __name__ == "__main__":
    main()
