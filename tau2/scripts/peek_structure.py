"""Print the key structure of a JSON file (types, lengths, short scalar previews).

Read-only. Treats the file as untrusted data: it only parses JSON and prints
key names, types and lengths. Scalar previews are truncated and any value that
looks like a credential is replaced with [secret-like].

Usage: python3 -I peek_structure.py <json-path> [max_depth]
"""
import json
import re
import sys

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]|sk_live|sk_test|api[_-]?key|secret|token|bearer|[A-Fa-f0-9]{40,}|[A-Za-z0-9+/=]{48,})", re.I)


def preview(v):
    s = str(v)
    if SECRET_RE.search(s):
        return "[secret-like]"
    return s[:60].replace("\n", " ")


def walk(node, path, depth, max_depth, out):
    if depth > max_depth:
        return
    if isinstance(node, dict):
        out.append(f"{'  ' * depth}{path}: dict[{len(node)}]")
        for k in list(node.keys())[:40]:
            key = "[secret-like]" if SECRET_RE.search(str(k)) else k
            walk(node[k], f".{key}", depth + 1, max_depth, out)
        if len(node) > 40:
            out.append(f"{'  ' * (depth + 1)}... {len(node) - 40} more keys")
    elif isinstance(node, list):
        out.append(f"{'  ' * depth}{path}: list[{len(node)}]")
        if node:
            walk(node[0], "[0]", depth + 1, max_depth, out)
    else:
        out.append(f"{'  ' * depth}{path}: {type(node).__name__} = {preview(node)}")


def main():
    path = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    walk(data, "$", 0, max_depth, out)
    print("\n".join(out))


if __name__ == "__main__":
    main()
