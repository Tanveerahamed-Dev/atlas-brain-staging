"""Read-only audit of complete exact-SHA workflow receipts; defaults to push events."""
import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path

REPO = "Tanveerahamed-Dev/atlas-brain-staging"


def workflow_paths(tree):
    if tree.get("truncated") is not False:
        raise ValueError("truncated source registry")
    return {r["path"] for r in tree["tree"] if r["type"] == "blob"
            and re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", r["path"])}


def expected_jobs(data, path, event):
    """Closed workflow header grammar; unknown matrices/names/conditions refuse."""
    blob = data["sources"][path]
    raw = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    entry = next(r for r in data["tree"]["tree"] if r["path"] == path)
    if blob["encoding"] != "base64" or digest != blob["sha"] or digest != entry["sha"]:
        raise ValueError("workflow blob does not match exact source tree")
    text = raw.decode("utf-8")
    if "\t" in text or re.findall(r"(?m)^jobs:.*$", text) != ["jobs:"]:
        raise ValueError("unsupported jobs declaration")
    blocks = re.split(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):\n", text.split("\njobs:\n", 1)[1])
    if blocks[0] or len(blocks) == 1:
        raise ValueError("empty or unsupported job registry")
    names = []
    for job, body in zip(blocks[1::2], blocks[2::2], strict=True):
        header, steps = body.split("    steps:\n", 1)
        header = re.sub(r"(?m)^ *#.*\n", "", header)
        pattern = (r"(?:    name: (.+)\n)?(?:    strategy:\n      fail-fast: false\n      matrix:\n        os: (.+)\n)?"
                   r"    runs-on: (.+)\n    timeout-minutes: [1-9][0-9]*(?: #[^\n]*)?\n")
        match = re.fullmatch(pattern, header)
        if not match or any(line and not line.startswith("      ") for line in steps.splitlines()):
            raise ValueError("unsupported job header or steps layout")
        label, matrix, runner = match.groups()
        if event == "workflow_dispatch" and label is None:
            raise ValueError("manual job lacks an event-bound context name")
        if label is not None:
            label_match = re.fullmatch(r"\$\{\{ github.event_name == 'workflow_dispatch' && 'manual-([A-Za-z0-9_-]+)'"
                                      r" \|\| '([A-Za-z0-9_-]+)' \}\}( \(\$\{\{ matrix.os \}\}\))?", label)
            if not label_match or label_match[1] != job or label_match[2] != job or bool(label_match[3]) != bool(matrix):
                raise ValueError("unbound or colliding manual job context")
            job = ("manual-" if event == "workflow_dispatch" else "") + job
        if matrix is None:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", runner):
                raise ValueError("unresolved runner")
            names.append(job)
            continue
        if runner != "${{ matrix.os }}":
            raise ValueError("unbound matrix runner")
        if matrix.startswith("${{"):
            expression = re.fullmatch(r"\$\{\{ fromJSON\(\(github.event_name == 'push' \|\| github.event_name == 'schedule'"
                                      r"( \|\| github.event_name == 'workflow_dispatch')?"
                                      r" \|\| vars.BOOTSTRAP_PR_LINUX_ONLY == 'false'\) && '(\[[^']+\])'"
                                      r" \|\| '(\[[^']+\])'\) \}\}", matrix)
            if not expression or not (event in {"push", "schedule"} or (event == "workflow_dispatch" and expression[1])):
                raise ValueError("unresolved matrix expression for event")
            values = json.loads(expression[2])
        else:
            if not re.fullmatch(r"\[[A-Za-z0-9_.-]+(?:, [A-Za-z0-9_.-]+)*\]", matrix):
                raise ValueError("unsupported matrix")
            values = matrix[1:-1].split(", ")
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
            raise ValueError("invalid matrix values")
        names.extend(f"{job} ({value})" for value in values)
    if len(set(names)) != len(names):
        raise ValueError("duplicate configured jobs")
    return sorted(names)


def select_runs(data, sha, event):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("unbound SHA")
    paths = workflow_paths(data["tree"])
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
    expected = {}
    for path, run in selected.items():
        jobs = data["jobs"][str(run["id"])]
        expected[path] = expected_jobs(data, path, event)
        if sorted(j["name"] for j in jobs) != expected[path]:
            raise ValueError(f"missing, duplicate or unexpected configured jobs: {path}")
        if not jobs or any(j["status"] != "completed" or j["conclusion"] != "success" for j in jobs):
            raise ValueError(f"missing, failed, pending, skipped or cancelled jobs: {path}")
        count += len(jobs)
    return {"verified": True, "sha": sha, "event": event, "workflow_count": len(selected),
            "job_count": count, "run_ids": [r["id"] for r in selected.values()], "expected_jobs": expected}


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
            entries = {r["path"]: r for r in data["tree"]["tree"]}
            data["sources"] = {p: github(f"git/blobs/{entries[p]['sha']}") for p in selected}
            data["jobs"] = {str(r["id"]): github(f"actions/runs/{r['id']}/jobs?filter=latest&per_page=100", "jobs")
                            for r in selected.values()}
        result = verify(data, args.sha, args.event)
        result["source"] = "supplied snapshot (not authenticated)" if args.snapshot else "GitHub REST"
        print(json.dumps(result, sort_keys=True))
        return 0
    except (KeyError, TypeError, ValueError, IndexError, OSError, subprocess.CalledProcessError) as error:
        print(json.dumps({"verified": False, "sha": args.sha, "event": args.event, "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
