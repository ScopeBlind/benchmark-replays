#!/usr/bin/env python3
"""Build the policy directories under test from the frozen drafts.

Usage: python3 -I build_policies.py <drafts_dir> <agentdojo_suites_data_dir> <out_policies_dir>

For each suite: <out>/<suite>/A/A.cedar (part A only) and
<out>/<suite>/full/{A.cedar,BC.cedar} (parts A, B and C). The travel BC.cedar
placeholders are filled from the user: block of travel/environment.yaml with
whitespace and dashes removed. The values are never printed. Prints the
sha256 of every file written.
"""
import hashlib
import os
import re
import sys

SUITES = ("banking", "slack", "travel", "workspace")
PLACEHOLDERS = {
    "passport_number": "{{PASSPORT_NUMBER}}",
    "ID_number": "{{ID_NUMBER}}",
    "bank_account_number": "{{BANK_ACCOUNT_NUMBER}}",
    "credit_card_number": "{{CREDIT_CARD_NUMBER}}",
}


def identity_numbers(suites_dir):
    path = os.path.join(suites_dir, "travel", "environment.yaml")
    vals = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("inbox:"):
                break
            m = re.match(r'^\s+(passport_number|ID_number|bank_account_number|credit_card_number):\s*"?([^"\n]+)"?\s*$', line)
            if m:
                vals[m.group(1)] = re.sub(r"[\s-]+", "", m.group(2))
    if set(vals) != set(PLACEHOLDERS):
        raise SystemExit("travel identity numbers incomplete: found " + ",".join(sorted(vals)))
    for k, v in vals.items():
        if not re.fullmatch(r"[A-Za-z0-9]+", v):
            raise SystemExit("unexpected characters in " + k)
    return vals


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(hashlib.sha256(text.encode("utf-8")).hexdigest(), path)


def main():
    drafts, suites_dir, out = sys.argv[1], sys.argv[2], sys.argv[3]
    ids = identity_numbers(suites_dir)
    for suite in SUITES:
        a = open(os.path.join(drafts, suite, "A.cedar"), encoding="utf-8").read()
        bc = open(os.path.join(drafts, suite, "BC.cedar"), encoding="utf-8").read()
        if suite == "travel":
            for key, ph in PLACEHOLDERS.items():
                if bc.count(ph) != 1:
                    raise SystemExit("placeholder count wrong for " + key)
                bc = bc.replace(ph, ids[key])
        if re.search(r"\{\{[A-Z_]+\}\}", a + bc):
            raise SystemExit("unfilled placeholder in " + suite)
        write(os.path.join(out, suite, "A", "A.cedar"), a)
        write(os.path.join(out, suite, "full", "A.cedar"), a)
        write(os.path.join(out, suite, "full", "BC.cedar"), bc)


if __name__ == "__main__":
    main()
