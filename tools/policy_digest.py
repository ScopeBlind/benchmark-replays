"""Recompute protect-mcp's policy digest (construction "acta-policy-digest-v1").

The digest a receipt carries is computed over a manifest of file names and
file hashes, not over the file bytes directly:

  M = {"construction": "acta-policy-digest-v1", "engine": "cedar",
       "files": [{"name": <file name>, "sha256": <hex of the file's bytes>}, ...]}
  policy_digest = "sha256:" + hex(sha256(JCS(M)))      (files sorted by name)

So the digest can be recomputed from the files, or from a list of their
hashes when the files themselves are not at hand.

Usage:
  python3 -I tools/policy_digest.py <cedar dir> [<cedar dir> ...]
  python3 -I tools/policy_digest.py --registration tau2/registration-v1.json

The second form recomputes each digest named in the registration from the
file hashes the registration lists, and reports which listed files in the
directory beside it still have those hashes. Standard library only.
"""
import hashlib
import json
import os
import sys


def jcs(obj):
    # RFC 8785 for this manifest: ASCII keys, strings and lists only.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_from_hashes(pairs):
    files = sorted(({"name": n, "sha256": h} for n, h in pairs), key=lambda e: e["name"])
    manifest = {"construction": "acta-policy-digest-v1", "engine": "cedar", "files": files}
    return "sha256:" + hashlib.sha256(jcs(manifest).encode("utf-8")).hexdigest()


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def digest_dir(d):
    names = sorted(n for n in os.listdir(d) if n.endswith(".cedar"))
    if not names:
        raise SystemExit(f"no .cedar files in {d}")
    return digest_from_hashes((n, file_sha256(os.path.join(d, n))) for n in names)


def from_registration(path):
    reg = json.load(open(path))
    root = os.path.dirname(os.path.abspath(path))
    by_dir = {}
    for rel, h in reg["policy_files"].items():
        by_dir.setdefault(os.path.dirname(rel), []).append((os.path.basename(rel), h, rel))
    labels = {"tau2-retail-v1": "v1", "tau2-retail-v1-p5a": "p5a", "tau2-retail-v1-p5b": "p5b"}
    for d, entries in sorted(by_dir.items()):
        got = digest_from_hashes((n, h) for n, h, _ in entries)
        want = reg.get("policy_digests", {}).get(labels.get(os.path.basename(d), ""), "?")
        print(f"{d}: from registered hashes {got} | registered digest {want} | equal: {got == want}")
        for n, h, rel in sorted(entries):
            p = os.path.join(root, rel)
            state = "missing" if not os.path.exists(p) else ("same bytes" if file_sha256(p) == h else "differs")
            print(f"  {rel}: {state}")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--registration":
        from_registration(sys.argv[2])
    elif len(sys.argv) >= 2 and not sys.argv[1].startswith("-"):
        for d in sys.argv[1:]:
            print(digest_dir(d), d)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
