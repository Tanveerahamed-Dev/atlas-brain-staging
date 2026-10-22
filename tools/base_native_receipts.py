"""Enforced CI base qualification; never substitute a PR head's own not-yet-created push run."""
import argparse
import json
import re
import subprocess

from tools.main_receipts import collect, verify_native


def target(base, head, event):
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (base, head)):
        raise ValueError("exact base and checkout SHA required")
    if event in {"pull_request", "merge_group", "push"}:
        if base == head:
            raise ValueError("event base must precede checkout; no self-run dependency")
    elif event in {"schedule", "workflow_dispatch"}:
        if base != head:
            raise ValueError("scheduled/manual audit must qualify its exact checkout")
    else:
        raise ValueError("unsupported event binding")
    return base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--event", required=True)
    args = parser.parse_args()
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], encoding="utf-8").strip()
        base = target(args.base, head, args.event)
        subprocess.check_call(["git", "merge-base", "--is-ancestor", base, head])
        if args.event == "push":
            parent = subprocess.check_output(["git", "rev-parse", "HEAD^1"], encoding="utf-8").strip()
            if parent != base:
                raise ValueError("push base differs from the merge's first parent")
        result = verify_native(collect(base, "push", with_checks=True), base)
        result.update(base_sha=base, head_sha=head, source="GitHub REST native base receipts")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (KeyError, TypeError, ValueError, IndexError, OSError, subprocess.CalledProcessError) as error:
        print(json.dumps({"verified": False, "base_sha": args.base, "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
