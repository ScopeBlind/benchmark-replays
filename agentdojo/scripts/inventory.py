#!/usr/bin/env python3
"""Read-only inventory of AgentDojo run files.

Usage: python3 -I inventory.py <runs_dir> <out_json>

Treats every run file as untrusted data: parses JSON with the standard
library only, never imports or executes anything from the AgentDojo tree.
Writes one JSON summary and prints a short text summary.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

DOS_ATTACKS = {"dos", "captcha_dos", "felony_dos", "offensive_email_dos", "swearwords_dos"}


def text_of(content):
    """Message content as one string (old string format or new block list)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("content") or block.get("text") or ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)


def main():
    runs_dir, out_path = sys.argv[1], sys.argv[2]
    files = Counter()  # (model, suite, kind, attack) -> n
    labels = defaultdict(lambda: Counter())  # (model, suite, kind, attack) -> Counter of utility/security
    top_keys = Counter()
    tool_call_keys = Counter()
    tool_msg_keys = Counter()
    content_format = Counter()
    func_counts = defaultdict(Counter)  # suite -> function -> n
    arg_names = defaultdict(lambda: defaultdict(Counter))  # suite -> function -> arg -> n
    tool_errors = defaultdict(Counter)  # suite -> function -> n tool messages with error
    versions = Counter()  # (model, benchmark_version or None, package_version or None)
    prompts = defaultdict(Counter)  # (suite, user_task) -> prompt text -> n (honest runs)
    inj_ids = defaultdict(set)  # (model, suite) -> injection task ids seen in attack files
    user_ids = defaultdict(set)  # (model, suite) -> user task ids seen
    calls_per_kind = Counter()  # (suite, kind) -> total tool calls
    files_with_error = Counter()  # (model, suite, kind) -> n with top-level error
    parse_failures = []
    marker_hits = Counter()  # (model, suite, marker) -> n
    n_files = 0
    max_calls = Counter()

    for model in sorted(os.listdir(runs_dir)):
        mpath = os.path.join(runs_dir, model)
        if not os.path.isdir(mpath):
            continue
        for suite in sorted(os.listdir(mpath)):
            spath = os.path.join(mpath, suite)
            if not os.path.isdir(spath):
                continue
            for task in sorted(os.listdir(spath)):
                tpath = os.path.join(spath, task)
                if not os.path.isdir(tpath):
                    continue
                for attack in sorted(os.listdir(tpath)):
                    apath = os.path.join(tpath, attack)
                    if not os.path.isdir(apath):
                        continue
                    for fname in sorted(os.listdir(apath)):
                        if not fname.endswith(".json"):
                            continue
                        fpath = os.path.join(apath, fname)
                        n_files += 1
                        if task.startswith("injection_task_"):
                            kind = "injection_as_user"
                        elif attack == "none":
                            kind = "honest"
                        elif attack in DOS_ATTACKS:
                            kind = "dos_attack"
                        else:
                            kind = "attack"
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                d = json.load(f)
                        except Exception as e:  # noqa: BLE001
                            parse_failures.append([fpath, repr(e)[:200]])
                            continue
                        key = (model, suite, kind, attack)
                        files[key] += 1
                        for k in d.keys():
                            top_keys[k] += 1
                        u, s = d.get("utility"), d.get("security")
                        labels[key][f"utility={u}"] += 1
                        labels[key][f"security={s}"] += 1
                        labels[key][f"pair={u},{s}"] += 1
                        if d.get("error"):
                            files_with_error[(model, suite, kind)] += 1
                        versions[(model, d.get("benchmark_version"), d.get("agentdojo_package_version"))] += 1
                        if kind in ("attack", "dos_attack"):
                            inj_ids[(model, suite)].add(d.get("injection_task_id"))
                        if task.startswith("user_task_"):
                            user_ids[(model, suite)].add(task)
                        msgs = d.get("messages") or []
                        ncalls = 0
                        for i, m in enumerate(msgs):
                            role = m.get("role")
                            c = m.get("content")
                            content_format[(role, type(c).__name__)] += 1
                            if role == "user" and kind == "honest" and i <= 2:
                                prompts[(suite, task)][text_of(c).strip()[:600]] += 1
                            if role == "assistant":
                                for tc in m.get("tool_calls") or []:
                                    ncalls += 1
                                    tool_call_keys[tuple(sorted(tc.keys()))] += 1
                                    fn = tc.get("function")
                                    func_counts[suite][fn] += 1
                                    args = tc.get("args") or {}
                                    if isinstance(args, dict):
                                        for an in args.keys():
                                            arg_names[suite][fn][an] += 1
                            if role == "tool":
                                tool_msg_keys[tuple(sorted(m.keys()))] += 1
                                if m.get("error"):
                                    tc = m.get("tool_call") or {}
                                    tool_errors[suite][tc.get("function")] += 1
                        calls_per_kind[(suite, kind)] += ncalls
                        max_calls[(suite, kind)] = max(max_calls[(suite, kind)], ncalls)
                        # Version markers visible in the files themselves.
                        inj_text = " ".join(str(v) for v in (d.get("injections") or {}).values())
                        if suite == "banking" and kind == "honest" and task == "user_task_15":
                            first_user = next((text_of(m.get("content")) for m in msgs if m.get("role") == "user"), "")
                            if "US133000000121212121212" in first_user:
                                marker_hits[(model, suite, "ut15_landlord_is_attacker_iban(v1)")] += 1
                            elif "CA133012400231215421872" in first_user:
                                marker_hits[(model, suite, "ut15_landlord_CA133(v1.1.1+)")] += 1
                        if suite == "banking" and kind == "attack" and attack == "important_instructions":
                            if "If details of transactions are underspecified" in inj_text:
                                marker_hits[(model, suite, "banking_goal_v1.2_suffix")] += 1
                            else:
                                marker_hits[(model, suite, "banking_goal_v1_text")] += 1
                        if suite == "travel" and kind == "attack" and d.get("injection_task_id") == "injection_task_2" and attack == "important_instructions":
                            if "anytime on May 1st" in inj_text:
                                marker_hits[(model, suite, "travel_it2_v1.2_text")] += 1
                            else:
                                marker_hits[(model, suite, "travel_it2_v1_text")] += 1

    def keyed(counter):
        return [[list(k) if isinstance(k, tuple) else k, v] for k, v in sorted(counter.items(), key=lambda kv: str(kv[0]))]

    out = {
        "runs_dir": runs_dir,
        "n_files": n_files,
        "parse_failures": parse_failures,
        "files": keyed(files),
        "labels": [[list(k), dict(v)] for k, v in sorted(labels.items())],
        "top_keys": dict(top_keys),
        "tool_call_keys": keyed(tool_call_keys),
        "tool_msg_keys": keyed(tool_msg_keys),
        "content_format": keyed(content_format),
        "func_counts": {s: dict(c) for s, c in func_counts.items()},
        "arg_names": {s: {fn: dict(a) for fn, a in fns.items()} for s, fns in arg_names.items()},
        "tool_errors": {s: dict(c) for s, c in tool_errors.items()},
        "versions": keyed(versions),
        "injection_ids": {f"{m}|{s}": sorted(x for x in v if x) for (m, s), v in sorted(inj_ids.items())},
        "user_task_counts": {f"{m}|{s}": len(v) for (m, s), v in sorted(user_ids.items())},
        "calls_per_kind": keyed(calls_per_kind),
        "max_calls": keyed(max_calls),
        "files_with_error": keyed(files_with_error),
        "markers": keyed(marker_hits),
        "honest_prompts": {f"{s}|{t}": [[p, n] for p, n in c.most_common()] for (s, t), c in sorted(prompts.items())},
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("files parsed:", n_files, "parse failures:", len(parse_failures))
    print("wrote", out_path)


if __name__ == "__main__":
    main()
