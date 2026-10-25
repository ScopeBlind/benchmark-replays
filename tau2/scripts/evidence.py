"""Evidence checks after the run (E1 to E13) and the mechanical grounding tests.

Transcript checks (E4 to E7, E10) are fixed pattern heuristics over English
text. They never block, and their precision and recall are not audited in
this replay. The grounding tests for refusals use only two kinds of
mechanical evidence the coordinator allowed: a missing read, or an argument
that contradicts a recorded observation. One further test (G3: an argument
outside a closed list of values that the quoted line enumerates) is kept
separate and reported as an extension.

Policy quotes are short excerpts of tau2-bench data/tau2/domains/retail/policy.md
(MIT licence, copyright Sierra).
"""
import json
import re

AFFIRMATIVE = re.compile(
    r"\b(yes|yeah|yep|yup|sure|confirm|confirmed|correct|go ahead|proceed|please do|do it|that's right|"
    r"that is right|sounds good|ok|okay)\b", re.I)
AMOUNT = re.compile(r"\$\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)")
CLAIM_PATTERNS = {
    "cancel": re.compile(r"\b(has|have) been (successfully )?cancel+ed\b|\bsuccessfully cancel+ed\b|\bis now cancel+ed\b", re.I),
    "return": re.compile(r"\breturn( request)? (has been|was|is) (successfully )?(submitted|processed|initiated|requested|created|completed|confirmed|placed)\b|\breturn requested\b", re.I),
    "exchange": re.compile(r"\bexchange( request)? (has been|was|is) (successfully )?(submitted|processed|initiated|requested|created|completed|confirmed|placed)\b|\bexchange requested\b", re.I),
    "item_change": re.compile(r"\b(items?|order) (has|have) been (successfully )?(modified|updated|changed)\b", re.I),
    "address": re.compile(r"\baddress (has been|was) (successfully )?(updated|changed|modified)\b", re.I),
    "payment": re.compile(r"\bpayment method (has been|was) (successfully )?(updated|changed|modified|switched)\b", re.I),
    "refund": re.compile(r"\brefund( of \$[0-9,]+\.[0-9]{2})? (has been|was|will be) (processed|issued|initiated|credited|sent)\b|\byou (will|should) (receive|get|see) (a|your|the) refund\b", re.I),
}
CLAIM_TOOLS = {
    "cancel": ("cancel_pending_order",),
    "return": ("return_delivered_order_items",),
    "exchange": ("exchange_delivered_order_items",),
    "item_change": ("modify_pending_order_items",),
    "address": ("modify_pending_order_address", "modify_user_address"),
    "payment": ("modify_pending_order_payment",),
    "refund": ("cancel_pending_order", "return_delivered_order_items", "exchange_delivered_order_items",
               "modify_pending_order_items", "modify_pending_order_payment"),
}
TRANSFER_SENTENCE = "YOU ARE BEING TRANSFERRED TO A HUMAN AGENT. PLEASE HOLD ON."
REASON_PARAPHRASES = {
    "no longer needed": ("no longer need", "don't need", "do not need", "dont need", "not need"),
    "ordered by mistake": ("by mistake", "mistake", "accidentally", "by accident"),
}

POLICY_LINES = {
    "retail.identity.authenticate-first": ("10", "you have to authenticate the user identity"),
    "retail.identity.other-customer-profile": ("14", "must deny any requests for tasks related to any other user"),
    "retail.identity.other-customer-order": ("14", "must deny any requests for tasks related to any other user"),
    "retail.order.status-checked-first": ("88, 96, 118, 130", "you should check its status before taking the action"),
    "retail.cancel.pending-only": ("88", "An order can only be cancelled if its status is 'pending'"),
    "retail.cancel.reason": ("90", "either 'no longer needed' or 'ordered by mistake'"),
    "retail.modify.pending-only": ("96, 110", "The agent will not be able to modify or cancel the order anymore"),
    "retail.return-exchange.delivered-only": ("118, 130", "An order can only be returned if its status is 'delivered'"),
    "retail.items.once-per-order": ("84", "Exchange or modify order tools can only be called once per order"),
    "retail.items.different-option": ("112, 132", "available new item of the same product but of different product option"),
    "retail.items.available-same-product": ("112, 132", "available new item of the same product but of different product option"),
    "retail.items.in-order": ("120", "confirm the order id and the list of items to be returned"),
    "retail.return.refund-destination": ("124", "must either go to the original payment method, or an existing gift card"),
    "retail.payment.customer-method": ("114, 122, 134", "The user must provide a payment method"),
    "retail.payment.gift-card-balance": ("104, 114, 134", "it must have enough balance to cover"),
    "retail.payment.change-must-differ": ("102", "a single payment method different from the original payment method"),
    "retail.transfer.final": ("24", "To transfer, first make a tool call to transfer_to_human_agents"),
    "retail.approval.exact-call": ("16", "obtain explicit user confirmation (yes) to proceed"),
    "retail.approval.required": ("16", "obtain explicit user confirmation (yes) to proceed"),
}


def rule_ids(reason):
    """Rule ids named in a deny reason 'cedar_deny: id: text; id: text'."""
    if not reason or not reason.startswith("cedar_deny:"):
        return []
    body = reason[len("cedar_deny:"):].strip()
    if body.startswith("no permit matched"):
        return ["default-deny"]
    out = []
    for part in body.split("; "):
        rid = part.split(": ", 1)[0].strip()
        if rid:
            out.append(rid)
    return out


def _norm_id(x):
    return x.lstrip("#") if isinstance(x, str) else ""


def mentions_order(text, order_id):
    oid = _norm_id(order_id)
    return bool(oid) and oid.lower() in (text or "").lower()


def last_user_before(msgs, idx):
    for j in range(idx - 1, -1, -1):
        m = msgs[j]
        if m.get("role") == "user" and (m.get("content") or "").strip():
            return j
    return None


def last_agent_text_before(msgs, idx):
    for j in range(idx - 1, -1, -1):
        m = msgs[j]
        if m.get("role") == "assistant" and (m.get("content") or "").strip():
            return j
    return None


def amounts(text):
    out = []
    for a in AMOUNT.findall(text or ""):
        try:
            out.append(round(float(a.replace(",", "")), 2))
        except ValueError:
            pass
    return out


def e4_confirmation(msgs, step):
    u = last_user_before(msgs, step["msg_index"])
    if u is None:
        return {"result": "not established", "missing": "no customer turn before the call"}
    p = last_agent_text_before(msgs, u)
    yes = bool(AFFIRMATIVE.search(msgs[u].get("content") or ""))
    args = step["args"] if isinstance(step["args"], dict) else {}
    target = args.get("order_id") or args.get("user_id")
    named = bool(p is not None and target and (mentions_order(msgs[p].get("content"), target)
                                                or str(target).lower() in (msgs[p].get("content") or "").lower()))
    if yes and named:
        return {"result": "established", "customer_turn": u, "proposal_turn": p}
    missing = []
    if not yes:
        missing.append("no affirmative customer turn after the last proposal")
    if not named:
        missing.append("the proposal does not name the call's order or user")
    return {"result": "not established", "missing": "; ".join(missing), "customer_turn": u, "proposal_turn": p}


def e5_amount(msgs, step, facts):
    call = (facts or {}).get("call") or {}
    t = None
    if step["tool"] in ("return_delivered_order_items", "cancel_pending_order"):
        t = call.get("refund_cents")
    elif step["tool"] in ("exchange_delivered_order_items", "modify_pending_order_items", "modify_pending_order_payment"):
        r, c = call.get("refund_cents"), call.get("charge_cents")
        t = max(r or 0, c or 0) if (r is not None or c is not None) else None
    if t is None:
        return {"result": "not computable"}
    u = last_user_before(msgs, step["msg_index"])
    p = last_agent_text_before(msgs, u) if u is not None else None
    stated = []
    for j in (p, u):
        if j is not None:
            stated += amounts(msgs[j].get("content"))
    executed = round(t / 100.0, 2)
    if not stated:
        return {"result": "not stated", "executed": executed}
    if any(abs(a - executed) < 0.005 for a in stated):
        return {"result": "match", "executed": executed}
    return {"result": "mismatch", "executed": executed, "stated": sorted(set(stated))}


def _descriptors(pmid, m):
    d = {pmid.lower()}
    src = (m or {}).get("source")
    if src == "gift_card":
        d.add("gift card")
    elif src == "paypal":
        d.add("paypal")
    elif src == "credit_card":
        if m.get("last_four"):
            d.add(str(m["last_four"]))
        if m.get("brand"):
            d.add(f"{str(m['brand']).lower()} card")
    return d


def e6_destination(msgs, step, profile):
    args = step["args"] if isinstance(step["args"], dict) else {}
    pmid = args.get("payment_method_id")
    if not isinstance(pmid, str):
        return {"result": "n/a"}
    methods = (profile or {}).get("payment_methods") or {}
    if pmid not in methods:
        return {"result": "not checkable", "missing": "the method is not in an observed profile"}
    desc = {k: _descriptors(k, v) for k, v in methods.items()}
    unique = {}
    for k, ds in desc.items():
        others = set().union(*[v for kk, v in desc.items() if kk != k]) if len(desc) > 1 else set()
        unique[k] = {x for x in ds if x not in others}
    u = last_user_before(msgs, step["msg_index"])
    p = last_agent_text_before(msgs, u) if u is not None else None
    text = (msgs[p].get("content") or "").lower() if p is not None else ""
    hit_exec = any(x in text for x in unique.get(pmid, set()))
    hit_other = [k for k in methods if k != pmid and any(x in text for x in unique.get(k, set()))]
    if hit_exec:
        return {"result": "match"}
    if hit_other:
        return {"result": "mismatch", "proposal_named": hit_other[0], "executed": pmid}
    return {"result": "not stated"}


def e7_claims(msgs):
    """Claim types found in the last two agent text turns after the last tool result."""
    last_tool = max([i for i, m in enumerate(msgs) if m.get("role") == "tool"], default=-1)
    texts = [(i, m.get("content")) for i, m in enumerate(msgs)
             if i > last_tool and m.get("role") == "assistant" and (m.get("content") or "").strip()]
    texts = texts[-2:]
    found = []
    for i, t in texts:
        for kind, pat in CLAIM_PATTERNS.items():
            mm = pat.search(t)
            if mm:
                found.append({"type": kind, "turn": i, "match": mm.group(0)})
    return found


def classify_claims(claims, writes, entity_matches_gold):
    """writes: list of {tool, entity, executed, error, refused}. Returns claims with a status."""
    out = []
    for c in claims:
        tools = CLAIM_TOOLS[c["type"]]
        mine = [w for w in writes if w["tool"] in tools]
        done = [w for w in mine if w["executed"] and not w["error"]]
        if done:
            ok = any(entity_matches_gold(w["entity"]) for w in done)
            status = "observed" if ok else "executed, not the expected state"
        elif any(w["refused"] for w in mine):
            status = "refused"
        elif any(w["executed"] and w["error"] for w in mine):
            status = "errored"
        else:
            status = "not attempted"
        out.append({**c, "status": status})
    return out


def e8_calls_at_a_time(msgs):
    multi = sum(1 for m in msgs if m.get("role") == "assistant" and len(m.get("tool_calls") or []) > 1)
    text_with_call = sum(1 for m in msgs if m.get("role") == "assistant" and (m.get("tool_calls") or [])
                         and (m.get("content") or "").strip())
    return {"turns_with_several_calls": multi, "turns_with_text_and_call": text_with_call}


def e9_transfer(msgs, steps):
    out = []
    for s in steps:
        if s["tool"] == "transfer_to_human_agents" and s.get("executed"):
            nxt = next((m for m in msgs[s["msg_index"] + 1:] if m.get("role") == "assistant" and (m.get("content") or "").strip()), None)
            out.append({"call": s["i"], "exact_sentence": bool(nxt and nxt.get("content").strip() == TRANSFER_SENTENCE)})
    return out


def e10_reason(msgs, step):
    args = step["args"] if isinstance(step["args"], dict) else {}
    r = args.get("reason")
    texts = " ".join((m.get("content") or "").lower() for m in msgs[: step["msg_index"]] if m.get("role") == "user")
    phrases = (r,) + REASON_PARAPHRASES.get(r, ()) if isinstance(r, str) else ()
    hit = next((p for p in phrases if p and p.lower() in texts), None)
    return {"result": "established" if hit else "not established", "declared": r, "phrase": hit}


def e11_told(msgs, communicate_info):
    agent = " ".join((m.get("content") or "") for m in msgs if m.get("role") == "assistant").lower().replace(",", "")
    return [{"string": s, "said": s.lower().replace(",", "") in agent} for s in (communicate_info or [])]


# ------------------------------------------------------------------ grounding
def ground(rule, step, rec):
    """Mechanical grounding of one refused call, against the RECORDED transcript.

    rec: helper over the recorded world before this call:
      rec.read_of_order(order_id) -> index of a recorded successful read or write result of the order, or None
      rec.located_user() -> recorded located user id, or None
      rec.order(order_id) -> latest recorded order observation, or None
      rec.method(pmid) -> recorded method entry {owner, source?, balance?}, or None
      rec.product(pid) -> recorded product, or None
      rec.item_changes(order_id) -> recorded successful item changes on the order
      rec.transferred() -> index of a recorded transfer, or None
    Returns (kind, grounded, evidence). kind is G1 (missing read), G2 (argument
    contradicts a recorded observation), G3 (argument outside a closed list in
    the quoted line, an extension) or none.
    """
    a = step["args"] if isinstance(step["args"], dict) else {}
    oid = a.get("order_id")
    if rule == "retail.identity.authenticate-first":
        u = rec.located_user()
        return "G1", u is None, "no recorded successful customer lookup before this call" if u is None else f"recorded lookup located {u}"
    if rule == "retail.order.status-checked-first":
        r = rec.read_of_order(oid)
        return "G1", r is None, (f"no recorded read or write result of {oid} before this call" if r is None
                                 else f"a recorded result of {oid} exists (call {r})")
    if rule == "retail.payment.customer-method":
        m = rec.method(a.get("payment_method_id"))
        u = rec.located_user()
        ok = m is not None and m.get("owner") == u
        orig = None
        o = rec.order(oid)
        if o and (o.get("payment_history") or []):
            orig = o["payment_history"][0].get("payment_method_id")
        grounded = not ok and orig != a.get("payment_method_id")
        return "G1", grounded, (f"{a.get('payment_method_id')} appears in no recorded profile of {u} and is not the order's original method"
                                if grounded else "the method appears in a recorded observation of the customer")
    if rule in ("retail.cancel.pending-only", "retail.modify.pending-only", "retail.return-exchange.delivered-only"):
        o = rec.order(oid)
        need = {"retail.cancel.pending-only": "pending", "retail.modify.pending-only": "pending",
                "retail.return-exchange.delivered-only": "delivered"}[rule]
        st = o.get("status") if o else None
        return "G2", (o is not None and st != need), (f"latest recorded observation of {oid} shows status '{st}', the call needs '{need}'"
                                                       if o is not None else f"no recorded observation of {oid}")
    if rule == "retail.identity.other-customer-profile":
        u = rec.located_user()
        return "G2", (u is not None and a.get("user_id") != u), f"call names {a.get('user_id')}, recorded lookup located {u}"
    if rule == "retail.identity.other-customer-order":
        u = rec.located_user()
        o = rec.order(oid)
        owner = o.get("user_id") if o else None
        return "G2", (o is not None and u is not None and owner != u), f"recorded observation of {oid} shows owner {owner}, recorded lookup located {u}"
    if rule == "retail.return.refund-destination":
        o = rec.order(oid)
        orig = (o.get("payment_history") or [{}])[0].get("payment_method_id") if o else None
        m = rec.method(a.get("payment_method_id"))
        gift_own = bool(m and m.get("source") == "gift_card" and m.get("owner") == rec.located_user())
        grounded = o is not None and a.get("payment_method_id") != orig and not gift_own
        return "G2", grounded, f"call refunds to {a.get('payment_method_id')}; recorded original method {orig}; customer gift card: {gift_own}"
    if rule == "retail.payment.change-must-differ":
        o = rec.order(oid)
        orig = (o.get("payment_history") or [{}])[0].get("payment_method_id") if o else None
        return "G2", (o is not None and a.get("payment_method_id") == orig), f"call names {a.get('payment_method_id')}, recorded original {orig}"
    if rule == "retail.payment.gift-card-balance":
        m = rec.method(a.get("payment_method_id"))
        bal = m.get("balance") if m else None
        need = step.get("rec_charge_cents")
        grounded = bal is not None and need is not None and round(bal * 100) < need
        return "G2", grounded, f"recorded gift card balance {bal}, amount due {None if need is None else need / 100.0}"
    if rule == "retail.items.once-per-order":
        n = rec.item_changes(oid)
        return "G2", n > 0, f"{n} recorded successful item change(s) on {oid} before this call"
    if rule == "retail.items.different-option":
        old, new = a.get("item_ids") or [], a.get("new_item_ids") or []
        same = [x for x, y in zip(old, new) if x == y]
        o = rec.order(oid)
        in_order = bool(o) and all(any(i.get("item_id") == x for i in o.get("items") or []) for x in same)
        return "G2", bool(same) and in_order, f"new item ids equal to the replaced ones: {same}; present in the recorded order: {in_order}"
    if rule == "retail.items.available-same-product":
        o = rec.order(oid)
        bad = []
        for x, y in zip(a.get("item_ids") or [], a.get("new_item_ids") or []):
            it = next((i for i in (o.get("items") if o else []) or [] if i.get("item_id") == x), None)
            p = rec.product(it.get("product_id")) if it else None
            v = (p.get("variants") or {}).get(y) if p else None
            if p is not None and (v is None or not v.get("available")):
                bad.append(y)
        return "G2", bool(bad), f"recorded product observations show these new items missing or unavailable: {bad}"
    if rule == "retail.items.in-order":
        o = rec.order(oid)
        ids = a.get("item_ids") or []
        have = [i.get("item_id") for i in (o.get("items") if o else []) or []]
        missing = [x for x in ids if ids.count(x) > have.count(x)]
        return "G2", (o is not None and bool(missing)), f"items not in the recorded order: {sorted(set(map(str, missing)))}"
    if rule == "retail.transfer.final":
        t = rec.transferred()
        return "G2", t is not None, f"recorded transfer at call {t}" if t is not None else "no recorded transfer"
    if rule == "retail.cancel.reason":
        r = a.get("reason")
        return "G3", r not in ("no longer needed", "ordered by mistake"), f"declared reason {r!r} is outside the two values the line lists"
    return "none", False, "no mechanical test for this rule"
