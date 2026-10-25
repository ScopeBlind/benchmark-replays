"""C5 stability: the second pass must reproduce the first byte for byte.

Compares, per run, the stable digest (every call's tool, arguments, facts,
decision, reason, policy digest, gate-input hash, execution and result hash,
plus all findings and both database hashes) and the findings digest between
pass 1 and pass 2. Signatures, timestamps and request ids differ by design and
are not in the digest.

Usage: python3 -I c5.py --pass1 <runs dir> --pass2 <runs dir> --out c5.json
"""
import argparse
import json
import os


def load(d, tag):
    out = {}
    for f in sorted(os.listdir(d)):
        if f.startswith("results-") and f"-{tag}-" in f and f.endswith(".jsonl"):
            for l in open(os.path.join(d, f)):
                if l.strip():
                    r = json.loads(l)
                    out[r["run_id"]] = r
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pass1", required=True)
    ap.add_argument("--pass2", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    p1, p2 = load(a.pass1, "pass1"), load(a.pass2, "pass2")
    common = sorted(set(p1) & set(p2))
    diff = [r for r in common if (p1[r]["stable_digest"], p1[r]["findings_sha256"]) != (p2[r]["stable_digest"], p2[r]["findings_sha256"])]
    by_set = {}
    for r in common:
        s = p2[r]["set"]
        by_set.setdefault(s, [0, 0])
        by_set[s][0] += 1
        by_set[s][1] += r not in diff
    res = {"compared": len(common), "identical": len(common) - len(diff), "different": diff[:50],
           "by_set": {k: {"compared": v[0], "identical": v[1]} for k, v in by_set.items()},
           "missing_in_pass2": len(set(p2) - set(p1)), "pass": not diff and len(common) == len(p2)}
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
