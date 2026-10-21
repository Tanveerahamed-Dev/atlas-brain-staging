"""Missing, stale, failed or skipped main receipts cannot imply complete CI."""
import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from tools.main_receipts import verify

SHA = "a" * 40


def receipts():
    paths = [f".github/workflows/gate{i}.yml" for i in range(3)]
    return {"tree": {"truncated": False, "tree": [{"path": p, "type": "blob"} for p in paths]},
            "catalog": [{"id": i + 1, "path": p, "state": "active"} for i, p in enumerate(paths)],
            "runs": [{"id": i + 10, "workflow_id": i + 1, "head_sha": SHA, "event": "push",
                      "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"}
                     for i in range(3)],
            "jobs": {str(i + 10): [{"status": "completed", "conclusion": "success"}] for i in range(3)}}


def test_full_source_derived_class_passes():
    assert verify(receipts(), SHA, "push")["workflow_count"] == 3


@pytest.mark.parametrize("plant", ["absent", "one_missing", "stale", "schedule", "failure", "pending",
                                  "skipped", "cancelled", "no_jobs", "newer_red", "new_gate", "disabled", "truncated"])
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
    else:
        data["tree"]["truncated"] = True
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_real_cli_positive_and_missing_snapshot(tmp_path):
    path = tmp_path / "receipts.json"
    for data, expected in ((receipts(), 0), ({**receipts(), "runs": []}, 1)):
        path.write_text(json.dumps(data), encoding="utf-8")
        result = subprocess.run([sys.executable, "-m", "tools.main_receipts", "--sha", SHA,
                                 "--snapshot", str(path)], capture_output=True, text=True, check=False)
        assert result.returncode == expected
        assert json.loads(result.stdout)["verified"] is (expected == 0)


def test_every_workflow_preserves_source_and_context_binding():
    for path in Path(".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "  workflow_dispatch:" in text and "      source_sha:" in text
        assert text.count("- name: Bind checked source") == text.count("uses: actions/checkout@")
        assert "inputs.source_sha || github.event.pull_request.head.sha || github.sha" in text
        assert "inputs.source_sha && 'recovery-' || ''" in text


@pytest.mark.parametrize("plant", ["positive", "branch", "wrong_sha", "empty"])
def test_actual_workflow_source_binding_block(tmp_path, plant):
    text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(r"      - name: Bind checked source\n[\s\S]+?        run: \|\n((?:          .*\n)+)", text)
    assert match is not None
    script = "\n".join(line[10:] for line in match[1].splitlines())
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Synthetic", "-c",
                    "user.email=synthetic@example.invalid", "commit", "--allow-empty", "-qm", "source"], check=True)
    actual = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    expected = {"positive": actual, "branch": "main", "wrong_sha": "f" * 40, "empty": ""}[plant]
    result = subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path,
                            env={**os.environ, "EXPECTED_SOURCE": expected}, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) is (plant == "positive"), result.stderr
