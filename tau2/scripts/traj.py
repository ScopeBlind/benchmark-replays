"""Shared helpers: load result files, pair tool calls with results, canonical hashes."""
import hashlib
import json
import os

CHANGED_TASKS = {"12", "13", "18", "21", "59", "91", "107"}
MODELS = ("claude-3-7-sonnet-20250219", "gpt-4.1-2025-04-14", "gpt-4.1-mini-2025-04-14", "o4-mini-2025-04-16")


def model_of(path):
    return os.path.basename(path).split("_retail_")[0]


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def canon_sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def extract_steps(msgs):
    """Every tool call in message order, paired with its tool result by id (as tau2 pairs them)."""
    tool_idx = {}
    for j, m in enumerate(msgs):
        if m.get("role") == "tool":
            tool_idx.setdefault(m.get("id"), []).append(j)
    used = set()
    steps = []
    for j, m in enumerate(msgs):
        if m.get("role") in ("assistant", "user") and m.get("tool_calls"):
            for k, tc in enumerate(m["tool_calls"]):
                cands = [x for x in tool_idx.get(tc.get("id"), []) if x > j and x not in used]
                r = cands[0] if cands else None
                if r is not None:
                    used.add(r)
                steps.append({
                    "i": len(steps), "msg_index": j, "k": k, "call_id": tc.get("id"),
                    "tool": tc.get("name"), "args": tc.get("arguments"),
                    "requestor": tc.get("requestor") or ("assistant" if m.get("role") == "assistant" else "user"),
                    "result_index": r,
                    "rec_content": msgs[r].get("content") if r is not None else None,
                    "rec_error": bool(msgs[r].get("error")) if r is not None else None,
                })
    return steps


def group_end(msgs, msg_index):
    """Index of the last tool result that belongs to the assistant message at msg_index."""
    ids = {tc.get("id") for tc in msgs[msg_index].get("tool_calls") or []}
    last = msg_index
    for j in range(msg_index + 1, len(msgs)):
        if msgs[j].get("role") == "tool" and msgs[j].get("id") in ids:
            last = j
        elif msgs[j].get("role") != "tool":
            break
    return last
