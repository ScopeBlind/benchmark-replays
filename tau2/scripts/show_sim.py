"""Print a compact view of one simulation from a tau2 results file.

Read-only; the file is untrusted data. Text is truncated, and any value that
looks like a credential is masked before printing.

Usage: python3 -I show_sim.py <results.json> <task_id> <trial> [max_chars]
"""
import json
import re
import sys

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{8,}|sk_live|sk_test|api[_-]?key\s*[:=]|bearer\s+[A-Za-z0-9])", re.I)


def clip(text, n):
    s = "" if text is None else str(text)
    s = s.replace("\n", " | ")
    if SECRET_RE.search(s):
        return "[secret-like text masked]"
    return s if len(s) <= n else s[: n - 3] + "..."


def main():
    path, task_id, trial = sys.argv[1], sys.argv[2], int(sys.argv[3])
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 220
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    sims = [s for s in data["simulations"] if s["task_id"] == task_id and s["trial"] == trial]
    if not sims:
        print("no such simulation")
        return
    s = sims[0]
    ri = s.get("reward_info") or {}
    print(f"sim {s['id']} task {task_id} trial {trial} reward {ri.get('reward')} db_match {(ri.get('db_check') or {}).get('db_match')} term {s.get('termination_reason')}")
    for i, m in enumerate(s.get("messages") or []):
        role = m.get("role")
        if m.get("tool_calls"):
            for tc in m["tool_calls"]:
                print(f"[{i}] {role} CALL {tc.get('name')} {clip(json.dumps(tc.get('arguments'), sort_keys=True), n)}")
            if m.get("content"):
                print(f"[{i}] {role} (text with call) {clip(m.get('content'), n)}")
        elif role == "tool":
            print(f"[{i}] tool{' ERROR' if m.get('error') else ''} {clip(m.get('content'), n)}")
        else:
            print(f"[{i}] {role}: {clip(m.get('content'), n)}")


if __name__ == "__main__":
    main()
