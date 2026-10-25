"""Cross-check the reference environment with tau2's own code (database hashes only).

Run with the python of a separate tau2-bench install (the run used one at
commit 96a3ef92, whose retail tools, database and replay code equal v1.0.1's), under
`env -i HOME=<empty> PATH=/usr/bin:/bin`, from an empty working directory, inside
`sandbox-exec` with network denied. Defences in this file:
  * every socket entry point is replaced before anything else is imported; any
    network attempt is recorded, refused, and makes the script exit 5;
  * dotenv is neutralised before tau2 is imported, so no .env can load;
  * the tau2 package __init__ (which imports agents, litellm and the runner) is
    never executed: a stub package with the real __path__ lets only the needed
    submodules load; the script exits 6 if litellm, openai or anthropic appear.
It computes hashes with tau2's Environment.set_state / make_tool_call /
get_db_hash and never calls a model.

Usage: python -I tau2_crosscheck.py --tau2-src <src dir> --tasks tasks.json
         --results <file> [...] [--extra trajectories.jsonl] --out out.json
"""
import socket
import sys

ATTEMPTS = []


def _blocked(*a, **k):
    ATTEMPTS.append(repr(a)[:80])
    raise OSError("network disabled for the cross-check")


socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
socket.gethostbyname = _blocked

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import types  # noqa: E402

import dotenv  # noqa: E402

dotenv.load_dotenv = lambda *a, **k: False
dotenv.find_dotenv = lambda *a, **k: ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tau2-src", required=True)
    ap.add_argument("--tasks", required=True)
    ap.add_argument("--results", action="append", default=[])
    ap.add_argument("--extra")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    pkg = types.ModuleType("tau2")
    pkg.__path__ = [os.path.join(a.tau2_src, "tau2")]
    sys.modules["tau2"] = pkg
    from loguru import logger
    logger.remove()
    from tau2.data_model.message import AssistantMessage, SystemMessage, ToolMessage, UserMessage
    from tau2.domains.retail.data_model import RetailDB
    from tau2.domains.retail.environment import get_environment
    from tau2.domains.retail.utils import RETAIL_DB_PATH

    banned = [m for m in ("litellm", "openai", "anthropic") if m in sys.modules]
    if banned:
        print(json.dumps({"stop": "model client imported", "modules": banned}))
        sys.exit(6)

    base = RetailDB.load(RETAIL_DB_PATH)
    classes = {"assistant": AssistantMessage, "user": UserMessage, "tool": ToolMessage, "system": SystemMessage}

    def env():
        return get_environment(db=base.model_copy(deep=True))

    def gold_hash(actions):
        e = env()
        for x in actions or []:
            if x.get("name") in ("calculate",):
                continue
            try:
                e.make_tool_call(x["name"], requestor=x.get("requestor") or "assistant", **(x.get("arguments") or {}))
            except Exception:
                pass
        return e.get_db_hash()

    def predicted_hash(messages):
        msgs = [classes[m["role"]].model_validate(m) for m in messages if m.get("role") in classes]
        e = env()
        e.set_state(initialization_data=None, initialization_actions=None, message_history=msgs, strict=False)
        return e.get_db_hash()

    out = {"tau2_db_path": str(RETAIL_DB_PATH), "initial": env().get_db_hash(), "v101": {}, "embedded": {}, "sims": {}, "extra": {}, "errors": []}
    with open(a.tasks, "r", encoding="utf-8") as fh:
        for t in json.load(fh):
            out["v101"][t["id"]] = gold_hash((t.get("evaluation_criteria") or {}).get("actions"))
    for path in a.results:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        m = os.path.basename(path).split("_retail_")[0]
        out["embedded"][m] = {t["id"]: gold_hash((t.get("evaluation_criteria") or {}).get("actions")) for t in data["tasks"]}
        for s in data["simulations"]:
            try:
                out["sims"][s["id"]] = predicted_hash(s["messages"])
            except Exception as e:  # recorded, not fatal
                out["errors"].append({"sim": s["id"], "error": str(e)[:200]})
        del data
    if a.extra:
        with open(a.extra, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    try:
                        out["extra"][r["key"]] = predicted_hash(r["messages"])
                    except Exception as e:
                        out["errors"].append({"extra": r["key"], "error": str(e)[:200]})
    out["network_attempts"] = len(ATTEMPTS)
    out["model_clients_loaded"] = [m for m in ("litellm", "openai", "anthropic") if m in sys.modules]
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, sort_keys=True)
    print(json.dumps({"initial": out["initial"], "v101": len(out["v101"]), "sims": len(out["sims"]),
                      "extra": len(out["extra"]), "errors": len(out["errors"]),
                      "network_attempts": len(ATTEMPTS), "model_clients_loaded": out["model_clients_loaded"]}))
    if ATTEMPTS or out["model_clients_loaded"]:
        sys.exit(5)


if __name__ == "__main__":
    main()
