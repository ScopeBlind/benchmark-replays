#!/usr/bin/env python3
"""Owner-side allowlists from the UNINJECTED AgentDojo environments.

Usage: python3 -I owner_sets.py <agentdojo_suites_data_dir> <out_json>

<agentdojo_suites_data_dir> is .../src/agentdojo/data/suites. Reads YAML as
text with a small line parser (stdlib only, no PyYAML, nothing imported from
the AgentDojo tree). Only structured address fields are read for addresses:
transaction sender/recipient, e-mail sender/recipients/cc/bcc, calendar
participants, drive owner/shared_with, Slack users. Free text (bills, file
contents, message bodies) never contributes an address. Link hosts are taken
from pre-existing message, e-mail, event and file text with every injection
placeholder replaced by its default value, i.e. the environment as it is
before any attack.

No attack definition is read. The output must be identical whatever attack
or injection task is later replayed.
"""
import json
import os
import re
import sys

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
TLDS = "com|org|net|edu|gov|io|co|ly|me|info|biz|app|dev|ai|uk|de|fr|ch|eu|us|ca|au|jp|cn|ru|in|br|it|es|nl|se|no|fi|dk|pl|be|at|nz|za|xyz|site|online|top|link|click"
URLISH = re.compile(r"(?<![@\w.-])(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:" + TLDS + r")(?![a-z0-9-])(?:/[^\s\"'<>)]*)?", re.I)
LIST_KEYS = {"recipients", "cc", "bcc", "participants", "users", "channels"}
SCALAR_ADDR_KEYS = {"sender", "owner", "recipient", "iban", "account_email"}


def norm_email(s):
    return s.strip().strip('"').strip("'").lower()


def norm_host(s):
    s = s.strip().strip('"').strip("'").lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip(".")


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def vector_defaults(text):
    """Top-level key -> default string, from injection_vectors.yaml."""
    out, key = {}, None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_]+):\s*$", line)
        if m:
            key = m.group(1)
            continue
        m = re.match(r"^\s+default:\s*(.*)$", line)
        if m and key:
            v = m.group(1).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[key] = v
    return out


def uninjected(text, defaults):
    def sub(m):
        k = m.group(1)
        return defaults.get(k, m.group(0))
    return re.sub(r"\{([A-Za-z0-9_]+)\}", sub, text)


def structured_fields(text):
    """Yield (key, value) for scalar address keys, list items and shared_with keys."""
    cur_key, cur_indent = None, -1
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if cur_key is not None:
            if indent > cur_indent or (indent == cur_indent and line.startswith("- ")):
                if cur_key == "shared_with":
                    m = re.match(r'^"?([^":]+)"?\s*:', line)
                    if m:
                        yield ("shared_with", m.group(1))
                        continue
                elif line.startswith("- "):
                    yield (cur_key, line[2:].strip().strip('"').strip("'"))
                    continue
            cur_key = None
        if line.startswith("- "):
            line = line[2:].strip()
            indent += 2
        m = re.match(r'^([A-Za-z_]+):\s*(.*)$', line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k in LIST_KEYS or k == "shared_with":
            if v in ("", None):
                cur_key, cur_indent = k, indent
            elif v.startswith("["):
                for item in v.strip("[]").split(","):
                    item = item.strip().strip('"').strip("'")
                    if item:
                        yield (k, item)
        elif k in SCALAR_ADDR_KEYS and v:
            yield (k, v.strip('"').strip("'"))


def main():
    base, out_path = sys.argv[1], sys.argv[2]
    result = {}

    # banking
    b_text = read(os.path.join(base, "banking", "environment.yaml"))
    ibans = set()
    for k, v in structured_fields(b_text):
        if k in ("sender", "recipient", "iban") and IBAN.fullmatch(v.replace(" ", "").upper() or "x"):
            ibans.add(v.replace(" ", "").upper())
    result["banking"] = {"payees_on_file": sorted(ibans)}

    # slack
    s_text = read(os.path.join(base, "slack", "environment.yaml"))
    s_def = vector_defaults(read(os.path.join(base, "slack", "injection_vectors.yaml")))
    s_clean = uninjected(s_text, s_def)
    users, channels = set(), set()
    for k, v in structured_fields(s_clean):
        if k == "users":
            users.add(v)
        if k == "channels":
            channels.add(v)
    # link hosts from pre-existing message bodies only (not web pages)
    bodies = re.findall(r'^\s*body:\s*"(.*)"\s*$', s_clean, re.M)
    s_hosts = set()
    for body in bodies:
        for u in URLISH.findall(body):
            s_hosts.add(norm_host(u))
    result["slack"] = {"users_on_file": sorted(users), "channels_on_file": sorted(channels),
                        "link_hosts_on_file": sorted(s_hosts)}

    # travel
    t_text = read(os.path.join(base, "travel", "environment.yaml"))
    t_addr = set()
    for k, v in structured_fields(t_text):
        if k in ("sender", "recipients", "cc", "bcc", "participants", "account_email") and EMAIL.fullmatch(v):
            t_addr.add(norm_email(v))
    result["travel"] = {"emails_on_file": sorted(t_addr)}

    # workspace
    w_def = vector_defaults(read(os.path.join(base, "workspace", "injection_vectors.yaml")))
    w_addr, w_hosts = set(), set()
    for name in ("inbox.yaml", "calendar.yaml", "cloud_drive.yaml"):
        txt = uninjected(read(os.path.join(base, "workspace", "include", name)), w_def)
        for k, v in structured_fields(txt):
            if k in ("sender", "recipients", "cc", "bcc", "participants", "owner", "shared_with", "account_email") and EMAIL.fullmatch(v):
                w_addr.add(norm_email(v))
        for u in URLISH.findall(txt):
            w_hosts.add(norm_host(u))
    result["workspace"] = {"emails_on_file": sorted(w_addr), "own_domain": "bluesparrowtech.com",
                           "link_hosts_on_file": sorted(w_hosts)}

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, sort_keys=True)
    for suite, sets in result.items():
        print(suite, {k: (len(v) if isinstance(v, list) else v) for k, v in sets.items()})


if __name__ == "__main__":
    main()
