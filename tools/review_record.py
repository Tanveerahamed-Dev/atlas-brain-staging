"""Bind unsigned review records to Git diffs and separately supplied author evidence."""
import argparse
import json
import re
import subprocess
from pathlib import Path

from tools.governance import diff_digest


def identity(value, family_required=False):
    keys = {"model_id", "session_id", "model_family"}
    required = keys if family_required else keys - {"model_family"}
    if not isinstance(value, dict) or not required <= value.keys() <= keys or any(
        not isinstance(v, str) or not v.strip() for v in value.values()
    ):
        raise ValueError("AD-06: incomplete identity evidence")
    return value["model_id"], value["session_id"]


def verify(record, summary, authors, pairs):
    required = {"reviewer", "authors", "verdict", "diff_sha256", "base_sha", "head_sha"}
    if not isinstance(record, dict) or set(record) != required or record["verdict"] != "approve":
        raise ValueError("AD-06: missing, blocked or unsupported signed record")
    for key, length in (("base_sha", 40), ("head_sha", 40), ("diff_sha256", 64)):
        if not isinstance(record[key], str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", record[key], re.ASCII) or record[key] != summary[key]:
            raise ValueError("AD-06: stale commit or diff binding")
    reviewer = record["reviewer"]
    reviewer_id = identity(reviewer, True)
    if not isinstance(authors, list) or not authors or not isinstance(record["authors"], list):
        raise ValueError("AD-06: missing author evidence")
    expected = [identity(a, True) for a in authors]
    actual = [identity(a) for a in record["authors"]]
    if len(set(expected)) != len(expected) or sorted(actual) != sorted(expected):
        raise ValueError("AD-06: author set does not match supplied evidence")
    for author in authors:
        if reviewer_id[0] == author["model_id"] or reviewer_id[1] == author["session_id"]:
            raise ValueError("AD-06: author and reviewer are not independent")
        declared = next(a for a in record["authors"] if identity(a) == identity(author))
        if declared.get("model_family", author["model_family"]) != author["model_family"]:
            raise ValueError("AD-06: inconsistent author family")
        if reviewer["model_family"] == author["model_family"] and [author["model_id"], reviewer["model_id"]] not in pairs:
            raise ValueError("AD-06: same-family review has no approved model-pair deviation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--retroactive", action="store_true")
    args = parser.parse_args()
    try:
        cases = json.loads(args.evidence.read_text(encoding="utf-8"))
        pairs = json.loads(args.policy.read_text(encoding="utf-8"))["same_family_pairs"]
        if not isinstance(cases, list) or not cases or (args.retroactive and {c["item"] for c in cases} != set(range(1, 12))):
            raise ValueError("AD-06: required review corpus is incomplete")
        for case in cases:
            base, head = case["base_sha"], case["head_sha"]
            summary = {"base_sha": base, "head_sha": head, "diff_sha256": diff_digest(Path.cwd(), base, head)}
            verify(case["record"], summary, case["authors"], pairs)
        print(f"AD-06: {len(cases)} supplied records bind to their diffs; signatures not verified")
        return 0
    except (KeyError, ValueError, TypeError, OSError, subprocess.CalledProcessError):
        print("AD-06: review evidence refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
