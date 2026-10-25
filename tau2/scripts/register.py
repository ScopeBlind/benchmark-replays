"""Sign the registration receipt: what was frozen before the first replay.

Digests of the policy text, the Cedar files and their gate digests, every
script, the answer key, the planted set, the base selection, the vector table,
the design document, the pinned commits and both public keys, signed with the
local harness key. Nothing is anchored or published.

Usage: python3 -I register.py --version N [--note TEXT] [--design <design document>]
         [--gateway <dir>] [--data <dir>] [--base <dir>]
"""
import argparse
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replay as RP  # noqa: E402



def fsha(p):
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", type=int, default=1)
    ap.add_argument("--note", default="")
    ap.add_argument("--design", help="design document to record by sha256 (optional)")
    RP.add_path_args(ap)
    a = ap.parse_args()
    RP.set_paths(a)
    B = RP.BASE
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    gate = RP.Helper(os.path.join(B, "keys/gate.json"), os.path.join(B, "logs/helper-register.log"))
    digests = {lbl: gate.req({"op": "digest", "policy_dir": d})["policy_digest"] for lbl, d in
               (("v1", os.path.join(B, "policy/tau2-retail-v1")), ("p5a", os.path.join(B, "policy/tau2-retail-v1-p5a")),
                ("p5b", os.path.join(B, "policy/tau2-retail-v1-p5b")))}
    gate.close()
    reg = {
        "type": "tau2-retail-replay.registration", "version": a.version, "note": a.note,
        "tau2_bench_commit": "0c69df456a96aa76a1162591574dad9c427a34d7",
        "gateway_commit": "5bb9720", "protect_mcp": "0.32.2", "verify": "0.11.0 (05138ad)",
        "policy_text_sha256": fsha(os.path.join(RP.DATA, "domains/retail/policy.md")),
        "policy_digests": digests,
        "policy_files": {os.path.relpath(p, B): fsha(p) for p in sorted(glob.glob(os.path.join(B, "policy/*/*.cedar")))},
        "scripts": {os.path.basename(p): fsha(p) for p in sorted(glob.glob(os.path.join(scripts_dir, "*.py")) + glob.glob(os.path.join(scripts_dir, "*.mjs")))},
        "frozen": {os.path.basename(p): fsha(p) for p in sorted(glob.glob(os.path.join(B, "frozen/*.json")))},
        "design_doc_sha256": fsha(a.design) if a.design else None,
        "gate_public_key": open(os.path.join(B, "keys/gate.pub")).read().strip(),
        "harness_public_key": open(os.path.join(B, "keys/harness.pub")).read().strip(),
    }
    harness = RP.Helper(os.path.join(B, "keys/harness.json"), os.path.join(B, "logs/helper-register.log"))
    r = harness.req({"op": "observe", "tool": "harness.registration", "input": reg, "prev": None})
    harness.close()
    out = os.path.join(B, f"registration-v{a.version}.json")
    with open(out, "w") as fh:
        json.dump(reg, fh, indent=1, sort_keys=True)
    with open(os.path.join(B, f"registration-v{a.version}.receipt.jsonl"), "w") as fh:
        fh.write(r["receipt"] + "\n")
    print(json.dumps({"registration": out, "policy_digests": digests, "frozen": reg["frozen"], "request_id": r["request_id"]}, indent=1))


if __name__ == "__main__":
    main()
