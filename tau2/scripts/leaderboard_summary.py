"""Summarise retail entries in the tau2 leaderboard submission files (read-only).

Prints model name, organisation, date, version, user simulator, retail pass^1
and pass^4, and whether a retail trajectory file is declared. Contact fields
are never printed.

Usage: python3 -I leaderboard_summary.py <submissions dir>
"""
import glob
import json
import os
import sys


def main():
    root = sys.argv[1]
    rows = []
    for path in sorted(glob.glob(os.path.join(root, "*", "submission.json"))):
        if os.path.basename(os.path.dirname(path)).startswith("A_EXAMPLE"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:
            continue
        r = (d.get("results") or {}).get("retail")
        if not isinstance(r, dict):
            continue
        tf = (d.get("trajectory_files") or {}).get("retail") if isinstance(d.get("trajectory_files"), dict) else None
        m = d.get("methodology") or {}
        rows.append({
            "model": d.get("model_name"), "org": d.get("model_organization"), "date": d.get("submission_date"),
            "type": d.get("submission_type"), "version": m.get("tau2_bench_version"), "user_sim": m.get("user_simulator"),
            "pass_1": r.get("pass_1"), "pass_4": r.get("pass_4"),
            "trajectories_available": d.get("trajectories_available"), "retail_trajectory_file_declared": bool(tf),
        })
    print(f"submissions with retail results: {len(rows)}")
    print(f"declaring a retail trajectory file: {sum(1 for x in rows if x['retail_trajectory_file_declared'])}")
    versions = {}
    for x in rows:
        versions[str(x["version"])] = versions.get(str(x["version"]), 0) + 1
    print("tau2_bench_version:", versions)
    sims = {}
    for x in rows:
        sims[str(x["user_sim"])] = sims.get(str(x["user_sim"]), 0) + 1
    print("user simulators:", sims)
    for x in sorted(rows, key=lambda x: -(x["pass_1"] or 0))[:12]:
        print(f"  {x['model']!s:45.45} {x['org']!s:14.14} {x['date']!s:10.10} v{x['version']!s:6.6} pass^1 {x['pass_1']!s:6.6} pass^4 {x['pass_4']!s:6.6} traj {x['retail_trajectory_file_declared']}")


if __name__ == "__main__":
    main()
