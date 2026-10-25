"""Context builder: the facts the gate decides on, computed from observations only.

Contract: design/tau2-retail-refund.md section 1.2. Facts come only from results
of calls that ran earlier in the same run (each signed as an observation
receipt), never from the transcript. Money is integer cents; positions and
multiplicities become counts, because Cedar sets lose both. A fact that is
not established is left out, so the policy's `has` guards see it as absent.
"""
import hashlib
import json

ORDER_WRITES = (
    "cancel_pending_order",
    "modify_pending_order_address",
    "modify_pending_order_items",
    "modify_pending_order_payment",
    "return_delivered_order_items",
    "exchange_delivered_order_items",
)
WRITE_TOOLS = ORDER_WRITES + ("modify_user_address",)
ITEM_CHANGES = ("modify_pending_order_items", "exchange_delivered_order_items")
LOOKUPS = ("find_user_id_by_email", "find_user_id_by_name_zip")


def jcs(v):
    """RFC 8785 for the values this replay produces (no fractions in gate inputs)."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def call_digest(tool, args):
    return "sha256:" + sha256_hex(jcs({"tool": tool, "args": args}))


def cents(x):
    return int(round(float(x) * 100))


def _parse(content):
    try:
        return json.loads(content)
    except Exception:
        return None


class Session:
    def __init__(self, approval_mode=None, approvals=None):
        self.auth_user = None
        self.located = []
        self.transferred = False
        self.orders = {}
        self.profiles = {}
        self.products = {}
        self.methods = {}
        self.item_changes = {}
        self.approval_mode = approval_mode
        self.approvals = approvals
        self.write_ordinal = 0
        self.flags = []

    # ------------------------------------------------------------------ facts
    def facts(self, tool, args):
        a = args if isinstance(args, dict) else {}
        s = {"identities_located": len(self.located)}
        if self.auth_user is not None:
            s["auth_user"] = self.auth_user
        if self.transferred:
            s["transferred"] = True
        oid = a.get("order_id")
        order = self.orders.get(oid) if isinstance(oid, str) else None
        if order is not None:
            o = {"user_id": order.get("user_id"), "status": order.get("status")}
            ph = order.get("payment_history") or []
            if ph and isinstance(ph[0], dict) and isinstance(ph[0].get("payment_method_id"), str):
                o["original_payment_method"] = ph[0]["payment_method_id"]
            s["order"] = {k: v for k, v in o.items() if isinstance(v, str)}
        pmid = a.get("payment_method_id")
        if isinstance(pmid, str) and pmid in self.methods:
            m = self.methods[pmid]
            pm = {"owner": m["owner"]}
            if "source" in m:
                pm["source"] = m["source"]
                if m["source"] == "gift_card" and m.get("balance") is not None:
                    pm["balance_cents"] = cents(m["balance"])
            s["payment_method"] = pm
        if isinstance(oid, str):
            s["prior_item_changes_on_order"] = self.item_changes.get(oid, 0)
        s["call"] = self._call_facts(tool, a, order)
        if self.approval_mode:
            s["approval_mode"] = self.approval_mode
            if tool in WRITE_TOOLS and self.approvals is not None and self.write_ordinal < len(self.approvals):
                s["approval"] = {"call_digest": self.approvals[self.write_ordinal]}
        return s

    def _call_facts(self, tool, a, order):
        c = {"digest": call_digest(tool, a)}
        items = order.get("items") if isinstance(order, dict) else None
        if tool in ITEM_CHANGES:
            old = a.get("item_ids")
            new = a.get("new_item_ids")
            if isinstance(old, list) and isinstance(new, list):
                c["same_item_count"] = sum(1 for x, y in zip(old, new) if x == y)
                if isinstance(items, list):
                    c["missing_item_count"] = self._missing(old, items)
                    prods = []
                    for x in old:
                        it = next((i for i in items if i.get("item_id") == x), None)
                        prods.append(it.get("product_id") if it else None)
                    checked = all(p is not None and p in self.products for p in prods) and len(prods) > 0
                    c["products_checked"] = bool(checked)
                    if checked:
                        bad = 0
                        diff = 0.0
                        priced = True
                        for x, y, p in zip(old, new, prods):
                            variants = self.products[p].get("variants") or {}
                            v = variants.get(y) if isinstance(y, str) else None
                            if not v or not v.get("available"):
                                bad += 1
                                priced = False
                                continue
                            it = next((i for i in items if i.get("item_id") == x), None)
                            diff += float(v.get("price", 0)) - float(it.get("price", 0))
                        c["bad_new_item_count"] = bad
                        if priced:
                            d = cents(diff)
                            c["charge_cents"] = max(0, d)
                            c["refund_cents"] = max(0, -d)
        elif tool == "return_delivered_order_items":
            ids = a.get("item_ids")
            if isinstance(ids, list) and isinstance(items, list):
                c["missing_item_count"] = self._missing(ids, items)
                total = 0.0
                for x in ids:
                    it = next((i for i in items if i.get("item_id") == x), None)
                    if it:
                        total += float(it.get("price", 0))
                c["refund_cents"] = cents(total)
        elif tool == "cancel_pending_order" and isinstance(order, dict):
            c["refund_cents"] = cents(sum(float(p.get("amount", 0)) for p in order.get("payment_history") or []))
        elif tool == "modify_pending_order_payment" and isinstance(order, dict):
            ph = order.get("payment_history") or []
            if ph:
                amt = cents(ph[0].get("amount", 0))
                c["charge_cents"] = amt
                c["refund_cents"] = amt
        return c

    @staticmethod
    def _missing(ids, items):
        all_ids = [i.get("item_id") for i in items]
        n = 0
        for x in ids:
            try:
                if ids.count(x) > all_ids.count(x):
                    n += 1
            except Exception:
                n += 1
        return n

    # ------------------------------------------------------------ observation
    def after_decision(self, tool):
        if tool in WRITE_TOOLS:
            self.write_ordinal += 1

    def observe(self, tool, args, content, error):
        """Update the session from the result of a call that ran."""
        a = args if isinstance(args, dict) else {}
        if error:
            return
        if tool == "transfer_to_human_agents":
            self.transferred = True
            return
        if tool in LOOKUPS:
            uid = content.strip() if isinstance(content, str) else None
            if uid:
                if uid not in self.located:
                    self.located.append(uid)
                if self.auth_user is None:
                    self.auth_user = uid
                elif uid != self.auth_user:
                    self.flags.append({"flag": "second_identity_located", "user_id": uid})
            return
        res = _parse(content)
        if not isinstance(res, dict):
            return
        if tool in ("get_user_details", "modify_user_address") and isinstance(res.get("user_id"), str):
            uid = res["user_id"]
            self.profiles[uid] = res
            for pmid, m in (res.get("payment_methods") or {}).items():
                if not isinstance(m, dict):
                    continue
                entry = {"owner": uid, "source": m.get("source")}
                if m.get("source") == "gift_card":
                    entry["balance"] = m.get("balance")
                self.methods[pmid] = entry
            return
        if tool == "get_product_details" and isinstance(res.get("product_id"), str):
            self.products[res["product_id"]] = res
            return
        if (tool == "get_order_details" or tool in ORDER_WRITES) and isinstance(res.get("order_id"), str):
            oid = res["order_id"]
            prev = self.orders.get(oid)
            if prev is not None and tool in ORDER_WRITES:
                self._apply_gift_card_deltas(prev.get("payment_history") or [], res.get("payment_history") or [])
            self.orders[oid] = res
            owner = res.get("user_id")
            for p in res.get("payment_history") or []:
                pmid = p.get("payment_method_id") if isinstance(p, dict) else None
                if isinstance(pmid, str) and pmid not in self.methods and isinstance(owner, str):
                    self.methods[pmid] = {"owner": owner}
            if tool in ITEM_CHANGES:
                self.item_changes[oid] = self.item_changes.get(oid, 0) + 1
            if tool == "get_order_details" and self.auth_user is not None and owner != self.auth_user:
                self.flags.append({"flag": "read_other_customer_order", "order_id": oid, "owner": owner})

    def _apply_gift_card_deltas(self, before, after):
        """A write's new payment entries move gift card balances (payment debits, refund credits)."""
        for p in after[len(before):]:
            if not isinstance(p, dict):
                continue
            m = self.methods.get(p.get("payment_method_id"))
            if not m or m.get("source") != "gift_card" or m.get("balance") is None:
                continue
            amt = float(p.get("amount", 0))
            if p.get("transaction_type") == "payment":
                m["balance"] = round(m["balance"] - amt, 2)
            elif p.get("transaction_type") == "refund":
                m["balance"] = round(m["balance"] + amt, 2)
