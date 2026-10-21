"""Missing, stale, failed or skipped main receipts cannot imply complete CI."""
import base64
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from tools.main_receipts import expected_jobs, verify

SHA = "a" * 40
SOURCE = """name: Synthetic
on: [push]
jobs:
  check:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    timeout-minutes: 10
    steps:
      - run: echo synthetic
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: echo synthetic
"""


def source_blob(text):
    raw = text.encode()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    return {"sha": digest, "encoding": "base64", "content": base64.b64encode(raw).decode()}


def receipts():
    paths = [f".github/workflows/gate{i}.yml" for i in range(3)]
    blob = source_blob(SOURCE)
    return {"tree": {"truncated": False, "tree": [{"path": p, "type": "blob", "sha": blob["sha"]} for p in paths]},
            "sources": {p: deepcopy(blob) for p in paths},
            "catalog": [{"id": i + 1, "path": p, "state": "active"} for i, p in enumerate(paths)],
            "runs": [{"id": i + 10, "workflow_id": i + 1, "head_sha": SHA, "event": "push",
                      "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"}
                     for i in range(3)],
            "jobs": {str(i + 10): [{"name": n, "status": "completed", "conclusion": "success"}
                                  for n in ("check (ubuntu-latest)", "check (windows-latest)", "audit")]
                     for i in range(3)}}


def test_full_source_derived_class_passes():
    result = verify(receipts(), SHA, "push")
    assert result["workflow_count"] == 3 and result["job_count"] == 9


def test_matrix_values_come_from_source_not_an_os_list():
    data = receipts()
    for entry in data["tree"]["tree"]:
        blob = source_blob(SOURCE.replace("windows-latest", "other-runner"))
        data["sources"][entry["path"]] = blob
        entry["sha"] = blob["sha"]
    for jobs in data["jobs"].values():
        jobs[1]["name"] = "check (other-runner)"
    assert verify(data, SHA, "push")["job_count"] == 9


@pytest.mark.parametrize("plant", ["windows", "job", "duplicate", "extra", "unbound", "tampered",
                                  "dynamic", "include", "condition", "renamed", "controller"])
def test_exact_source_job_inventory_refusals(plant):
    data = receipts()
    path = data["catalog"][0]["path"]
    if plant in {"windows", "job"}:
        data["jobs"]["10"].pop(1 if plant == "windows" else 2)
    elif plant in {"duplicate", "extra"}:
        data["jobs"]["10"].append({**data["jobs"]["10"][0], "name": "extra" if plant == "extra" else "audit"})
    elif plant == "unbound":
        data["sources"][path]["sha"] = "b" * 40
    elif plant == "tampered":
        data["sources"][path]["content"] = base64.b64encode(b"jobs:\n").decode()
    elif plant == "controller":
        data["runs"][0]["head_sha"] = "b" * 40
    else:
        replacement = {"dynamic": "${{ needs.build.outputs.os }}", "include": "[]\n        include: []",
                       "condition": "[ubuntu-latest, windows-latest]\n    if: false",
                       "renamed": "[other-os]"}[plant]
        blob = source_blob(SOURCE.replace("[ubuntu-latest, windows-latest]", replacement))
        data["sources"][path] = blob
        data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


@pytest.mark.parametrize("plant", ["absent", "one_missing", "stale", "schedule", "failure", "pending",
                                  "skipped", "cancelled", "no_jobs", "newer_red", "new_gate", "disabled",
                                  "duplicate_catalog", "bad_identity", "truncated"])
def test_main_receipt_refusals(plant):
    data = receipts()
    if plant == "absent":
        data["runs"] = []
    elif plant == "one_missing":
        data["runs"].pop()
    elif plant == "stale":
        data["runs"][0]["head_sha"] = "b" * 40
    elif plant == "schedule":
        data["runs"][0]["event"] = "schedule"
    elif plant == "failure":
        data["runs"][0]["conclusion"] = "failure"
    elif plant == "pending":
        data["runs"][0]["status"] = "in_progress"
    elif plant in {"skipped", "cancelled"}:
        data["jobs"]["10"][0]["conclusion"] = plant
    elif plant == "no_jobs":
        data["jobs"]["10"] = []
    elif plant == "newer_red":
        data["runs"].append({**deepcopy(data["runs"][0]), "id": 99, "run_number": 2, "conclusion": "failure"})
    elif plant == "new_gate":
        data["tree"]["tree"].append({"path": ".github/workflows/new.yml", "type": "blob"})
    elif plant == "disabled":
        data["catalog"][0]["state"] = "disabled_manually"
    elif plant == "duplicate_catalog":
        data["catalog"].append(deepcopy(data["catalog"][0]))
    elif plant == "bad_identity":
        data["catalog"][0]["id"] = True
    else:
        data["tree"]["truncated"] = True
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_real_cli_positive_and_missing_snapshot(tmp_path: Path):
    path = tmp_path / "receipts.json"
    omitted = receipts()
    omitted["jobs"]["10"].pop(1)
    for data, expected in ((receipts(), 0), ({**receipts(), "runs": []}, 1), (omitted, 1)):
        path.write_text(json.dumps(data), encoding="utf-8")
        result = subprocess.run([sys.executable, "-m", "tools.main_receipts", "--sha", SHA,
                                 "--snapshot", str(path)], capture_output=True, text=True, check=False)
        assert result.returncode == expected
        assert json.loads(result.stdout)["verified"] is (expected == 0)


@pytest.mark.parametrize("sha,expected", [("a293f540eb75d11c8849736302bfeea183cdfb61", 0),
                                         ("228a16b7197e75253cf2426d700cf23eb8c3b13f", 1)])
def test_live_published_positive_and_missing_push_history(sha, expected):
    result = subprocess.run([sys.executable, "-m", "tools.main_receipts", "--sha", sha],
                            capture_output=True, text=True, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    record = json.loads(result.stdout)
    assert record["sha"] == sha and record["event"] == "push"
    assert record["verified"] is (expected == 0)
    if expected:
        assert "missing exact-SHA push receipt" in record["reason"]


def test_every_registered_workflow_has_one_explicit_manual_recovery_trigger():
    for path in Path(".github/workflows").iterdir():
        if path.suffix not in {".yml", ".yaml"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert text.count("  workflow_dispatch:\n") == 1
        assert "github.event.pull_request.head.sha || github.sha" in text
        blob = source_blob(text)
        data = {"sources": {path.as_posix(): blob},
                "tree": {"tree": [{"path": path.as_posix(), "sha": blob["sha"]}]}}
        ordinary = expected_jobs(data, path.as_posix(), "push")
        manual = expected_jobs(data, path.as_posix(), "workflow_dispatch")
        assert len(manual) == len(ordinary) and set(manual).isdisjoint(ordinary)
        assert all(name.startswith("manual-") for name in manual)


def test_yaml_workflow_cannot_escape_manual_context_class(tmp_path: Path, monkeypatch):
    source = Path(".github/workflows/governance.yml").read_text(encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "valid.yml").write_text(source, encoding="utf-8")
    yaml_path = workflows / "planted.yaml"
    yaml_path.write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    test_every_registered_workflow_has_one_explicit_manual_recovery_trigger()
    yaml_path.write_text(source.replace("'manual-governance-foundation'", "'governance-foundation'"), encoding="utf-8")
    with pytest.raises((ValueError, AssertionError)):
        test_every_registered_workflow_has_one_explicit_manual_recovery_trigger()


@pytest.mark.parametrize("event,prefix", [("push", ""), ("schedule", ""), ("workflow_dispatch", "manual-")])
def test_event_bound_job_names_have_positive_receipts(event, prefix):
    data = receipts()
    text = SOURCE
    for job, suffix in (("check", " (${{ matrix.os }})"), ("audit", "")):
        expression = "${{ github.event_name == 'workflow_dispatch' && 'manual-" + job + "' || '" + job + "' }}" + suffix
        text = text.replace(f"  {job}:\n", f"  {job}:\n    name: {expression}\n")
    blob = source_blob(text)
    for entry in data["tree"]["tree"]:
        entry["sha"] = blob["sha"]
        data["sources"][entry["path"]] = blob
    for run in data["runs"]:
        run["event"] = event
    for jobs in data["jobs"].values():
        for job in jobs:
            job["name"] = prefix + job["name"]
    assert verify(data, SHA, event)["job_count"] == 9
    if prefix:
        data["jobs"]["10"][0]["name"] = "check (ubuntu-latest)"
        with pytest.raises(ValueError):
            verify(data, SHA, event)


def test_manual_context_collision_is_refused():
    data = receipts()
    text = SOURCE.replace("  audit:\n", "  audit:\n    name: ${{ github.event_name == 'workflow_dispatch' && 'audit' || 'audit' }}\n")
    blob = source_blob(text)
    path = data["catalog"][0]["path"]
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")
