"""Read-only audit of complete exact-SHA workflow receipts; defaults to push events."""
import argparse
import json
import re
import subprocess
from pathlib import Path

REPO = "Tanveerahamed-Dev/atlas-brain-staging"


def select_runs(data, sha, event):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or data["tree"].get("truncated") is not False:
        raise ValueError("unbound SHA or truncated source registry")
    paths = {r["path"] for r in data["tree"]["tree"] if r["type"] == "blob"
             and re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", r["path"])}
    catalog = {r["path"]: r for r in data["catalog"]}
    if not paths or any(p not in catalog or catalog[p]["state"] != "active" for p in paths):
        raise ValueError("empty, missing or disabled workflow registry")
    rows = [r for r in data["catalog"] if r["path"] in paths]
    if len(rows) != len(paths) or any(type(r["id"]) is not int or r["id"] < 1 for r in rows):
        raise ValueError("duplicate or invalid workflow registry identity")
    if len({catalog[p]["id"] for p in paths}) != len(paths):
        raise ValueError("ambiguous workflow identities")
    selected = {}
    for path in sorted(paths):
        rows = [r for r in data["runs"] if r["workflow_id"] == catalog[path]["id"]
                and r["head_sha"] == sha and r["event"] == event]
        if not rows:
            raise ValueError(f"missing exact-SHA {event} receipt: {path}")
        if any(any(type(r[k]) is not int or r[k] < 1 for k in ("id", "workflow_id", "run_number", "run_attempt")) for r in rows):
            raise ValueError("invalid workflow run identity")
        run = max(rows, key=lambda r: (r["run_number"], r["run_attempt"]))
        if run["status"] != "completed" or run["conclusion"] != "success":
            raise ValueError(f"latest workflow is not successful: {path}")
        selected[path] = run
    return selected


def verify(data, sha, event):
    selected = select_runs(data, sha, event)
    count = 0
    for path, run in selected.items():
        jobs = data["jobs"][str(run["id"])]
        if not jobs or any(j["status"] != "completed" or j["conclusion"] != "success" for j in jobs):
            raise ValueError(f"missing, failed, pending, skipped or cancelled jobs: {path}")
        count += len(jobs)
    return {"verified": True, "sha": sha, "event": event, "workflow_count": len(selected),
            "job_count": count, "run_ids": [r["id"] for r in selected.values()]}


def github(endpoint, key=None):
    command = ["gh", "api", f"repos/{REPO}/{endpoint}"]
    if key:
        pages = json.loads(subprocess.check_output([*command, "--paginate", "--slurp"], encoding="utf-8"))
        return [row for page in pages for row in page[key]]
    return json.loads(subprocess.check_output(command, encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--event", choices=("push", "schedule", "workflow_dispatch"), default="push")
    parser.add_argument("--snapshot", type=Path, help="Supplied unauthenticated self-test snapshot; no live evidence claim")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
            raise ValueError("exact SHA required")
        if args.snapshot:
            data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        else:
            data = {"tree": github(f"git/trees/{args.sha}?recursive=1"),
                    "catalog": github("actions/workflows?per_page=100", "workflows"),
                    "runs": github(f"actions/runs?head_sha={args.sha}&per_page=100", "workflow_runs")}
            selected = select_runs(data, args.sha, args.event)
            data["jobs"] = {str(r["id"]): github(f"actions/runs/{r['id']}/jobs?filter=latest&per_page=100", "jobs")
                            for r in selected.values()}
        result = verify(data, args.sha, args.event)
        result["source"] = "supplied snapshot (not authenticated)" if args.snapshot else "GitHub REST"
        print(json.dumps(result, sort_keys=True))
        return 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(json.dumps({"verified": False, "sha": args.sha, "event": args.event, "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
