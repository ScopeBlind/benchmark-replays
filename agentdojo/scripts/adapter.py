#!/usr/bin/env python3
"""Replay adapter: AgentDojo tool calls to protect-mcp evaluate inputs.

Usage: python3 -I adapter.py <runs_dir> <out_dir>

Implements section 4.2 of design/agentdojo-gate-replay.md. For every honest,
non-DoS attack and injection-as-user trace it reads message 1 (the user's
request) and the tool calls, and writes:

  <out_dir>/traces.jsonl    one line per trace: id, path parts, sha256 of
                            message 1, sha256 of the request facts, call count
  <out_dir>/calls.jsonl.gz  one line per call: trace id, call index, suite,
                            tool, args as recorded, facts (the --context JSON)

Facts are computed by facts_for(request_text, tool, args) and nothing else:
no tool output, no injection field, no label and no task id reaches it. The
path parts only label the output. Run files are untrusted data and are only
parsed with json.
"""
import gzip
import hashlib
import json
import os
import re
import sys

DOS = {"dos", "captcha_dos", "felony_dos", "offensive_email_dos", "swearwords_dos"}

TLDS = "com|org|net|edu|gov|io|co|ly|me|info|biz|app|dev|ai|uk|de|fr|ch|eu|us|ca|au|jp|cn|ru|in|br|it|es|nl|se|no|fi|dk|pl|be|at|nz|za|xyz|site|online|top|link|click"
URL_RE = re.compile(r"(?<![@\w.-])(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:" + TLDS + r")(?![a-z0-9-])(?:/[^\s\"'<>)]*)?", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
WORD_RE = re.compile(r"[a-z][a-z0-9_-]*")
ASKS = {
    "delete": re.compile(r"\b(delet|remov|eras|trash|kick)\w*", re.I),
    "book": re.compile(r"\b(book|reserv)\w*", re.I),
    "calendar": re.compile(r"\b(calendar|remind)\w*", re.I),
}
TOKEN_STRIP = ".,;:!?()[]{}\"'"
# ASCII hyphen plus the Unicode hyphens and dashes, built from code points so
# this file stays ASCII.
DASHES = "-" + "".join(chr(c) for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212))
COMPACT_RE = re.compile("[\\s" + re.escape(DASHES) + "]+")

MONEY_TOOLS = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
WEB_TOOLS = {"post_webpage", "get_webpage"}
MAIL_FIELDS = ("recipients", "cc", "bcc")
PARTICIPANT_TOOLS = {"create_calendar_event", "add_calendar_event_participants"}
VENUE_FIELD = {"reserve_hotel": "hotel", "reserve_restaurant": "restaurant", "reserve_car_rental": "company"}
TEXT_FIELDS = {
    "send_email": ("subject", "body"),
    "send_direct_message": ("body",),
    "send_channel_message": ("body",),
    "post_webpage": ("content",),
    "create_calendar_event": ("title", "description", "location"),
}


def text_of(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(b.get("content") or "") if isinstance(b, dict) else str(b) for b in content)
    return str(content)


def norm_host(u):
    s = str(u).strip().strip('"').strip("'").lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip(".")


def norm_iban(v):
    return re.sub(r"\s+", "", str(v)).upper()


def as_items(v):
    """A list field or a comma/semicolon separated string, as trimmed lowercase items."""
    if v is None:
        return []
    if isinstance(v, list):
        items = [x if isinstance(x, str) else json.dumps(x, sort_keys=True, ensure_ascii=True) for x in v if x is not None]
    elif isinstance(v, str):
        items = re.split(r"[,;]", v)
    else:
        items = [json.dumps(v, sort_keys=True, ensure_ascii=True)]
    return [x.strip().lower() for x in items if x.strip()]


def request_view(request):
    """Everything the gate may learn from the user's request (message 1)."""
    return {
        "asks": {k: bool(rx.search(request)) for k, rx in ASKS.items()},
        "ibans": sorted(set(IBAN_RE.findall(request.upper()))),
        "emails": sorted({e.lower() for e in EMAIL_RE.findall(request)}),
        "hosts": sorted({norm_host(u) for u in URL_RE.findall(request)}),
        "words": sorted(set(WORD_RE.findall(request.lower()))),
        "tokens": sorted({t.strip(TOKEN_STRIP) for t in request.split()} - {""}),
        "collapsed": " ".join(request.lower().split()),
    }


def destinations(tool, args):
    """(kind, normalized destination) pairs named by this call."""
    out = []
    if tool in MONEY_TOOLS:
        r = args.get("recipient")
        if r is not None and norm_iban(r):
            out.append(("iban", norm_iban(r)))
    elif tool in WEB_TOOLS:
        u = args.get("url")
        if u is not None and norm_host(u):
            out.append(("host", norm_host(u)))
    elif tool == "send_direct_message":
        r = args.get("recipient")
        if r is not None and str(r).strip():
            out.append(("user", str(r).strip().lower()))
    if tool == "send_email":
        for f in MAIL_FIELDS:
            out += [("email", x) for x in as_items(args.get(f))]
    if tool in PARTICIPANT_TOOLS:
        out += [("email", x) for x in as_items(args.get("participants"))]
    if tool == "share_file":
        out += [("email", x) for x in as_items(args.get("email"))]
    return out


def call_text(tool, args):
    parts = []
    for f in TEXT_FIELDS.get(tool, ()):
        v = args.get(f)
        if v is None:
            continue
        parts.append(v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=True))
    return "\n".join(parts)


def facts_for(request, tool, args):
    """The --context facts for one call. A pure function of its three arguments."""
    rv = request_view(request)
    if not isinstance(args, dict):
        args = {}
    named = {"iban": set(rv["ibans"]), "email": set(rv["emails"]), "host": set(rv["hosts"]), "user": set(rv["words"])}
    dests_unnamed = sorted({d for kind, d in destinations(tool, args) if d not in named[kind]})
    target = False
    if tool == "update_password":
        pw = args.get("password")
        target = pw is not None and str(pw) in set(rv["tokens"])
    elif tool in VENUE_FIELD:
        v = args.get(VENUE_FIELD[tool])
        v = " ".join(str(v).lower().split()) if v is not None else ""
        target = len(v) >= 3 and v in rv["collapsed"]
    elif tool == "invite_user_to_slack":
        u = str(args.get("user") or "").strip().lower()
        target = bool(u) and u in set(rv["words"])
    text = call_text(tool, args)
    links_unnamed = sorted({norm_host(u) for u in URL_RE.findall(text)} - set(rv["hosts"]))
    return {
        "request": {"asks": rv["asks"]},
        "call": {
            "dests_unnamed": dests_unnamed,
            "links_unnamed": links_unnamed,
            "target_named": bool(target),
            "text": text,
            "text_compact": COMPACT_RE.sub("", text),
        },
    }


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def main():
    runs, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    tr = open(os.path.join(out_dir, "traces.jsonl"), "w", encoding="utf-8")
    calls_out = gzip.open(os.path.join(out_dir, "calls.jsonl.gz"), "wt", encoding="utf-8", compresslevel=6)
    tid = 0
    n_calls = 0
    non_dict_args = 0
    for pipeline in sorted(os.listdir(runs)):
        pp = os.path.join(runs, pipeline)
        if not os.path.isdir(pp):
            continue
        for suite in sorted(os.listdir(pp)):
            sp = os.path.join(pp, suite)
            for task in sorted(os.listdir(sp)):
                tp = os.path.join(sp, task)
                for attack in sorted(os.listdir(tp)):
                    ap = os.path.join(tp, attack)
                    if attack in DOS or not os.path.isdir(ap):
                        continue
                    for fname in sorted(os.listdir(ap)):
                        if not fname.endswith(".json"):
                            continue
                        with open(os.path.join(ap, fname), encoding="utf-8") as f:
                            d = json.load(f)
                        msgs = d.get("messages") or []
                        request = next((text_of(m.get("content")) for m in msgs if m.get("role") == "user"), "")
                        calls = []
                        for m in msgs:
                            if m.get("role") == "assistant":
                                calls.extend(m.get("tool_calls") or [])
                        tid += 1
                        rv = request_view(request)
                        tr.write(canon({"t": tid, "pipeline": pipeline, "suite": suite, "task": task, "attack": attack,
                                        "file": fname, "msg1_sha256": sha(request), "request_facts_sha256": sha(canon(rv)),
                                        "n_calls": len(calls)}) + "\n")
                        for i, tc in enumerate(calls):
                            tool = str(tc.get("function") or "")
                            args = tc.get("args")
                            if not isinstance(args, dict):
                                non_dict_args += 1
                                args = {} if args is None else args
                            calls_out.write(canon({"t": tid, "i": i, "suite": suite, "tool": tool, "args": args,
                                                   "facts": facts_for(request, tool, args)}) + "\n")
                            n_calls += 1
    tr.close()
    calls_out.close()
    print(json.dumps({"traces": tid, "calls": n_calls, "non_dict_args": non_dict_args}))


if __name__ == "__main__":
    main()
