import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import allowed


@pytest.mark.parametrize("path", [
    "outside.txt", "prompts/x.md", "tools/prompts/x.md", "docs/adr/BOARD.md",
    "tools/agent-notes.md", "tests/AGENTS.md", "tools/CLAUDE.md",
    "tools/.claude/x", "tools/.codex/x", "tools/.agents/x", "tools/.mcp.json",
    "tools/.specify/x", "tools/specs/x", "tools/plans/x", "docs/other.md",
    "governance/STATUS.md", "governance/STATUS.json", "governance/notes.txt", "governance/probe.json",
])
def test_planted_paths_fail(path):
    assert not allowed(path)
    result = subprocess.run(
        [sys.executable, "tools/fence.py", path], capture_output=True, check=False,
    )
    assert result.returncode == 1


@pytest.mark.parametrize("path", [
    "README.md", "uv.lock", "atlas_brain/__init__.py", "tests/test_fence.py",
    "fixtures/example.txt", "docs/adr/0000-plan-approval.md",
    "docs/contract/v1.json", "tools/fence.py", "governance/review.schema.json",
    ".github/workflows/ci.yml",
])
def test_allowed_paths(path):
    assert allowed(path)


def test_current_tree_passes():
    subprocess.run([sys.executable, "tools/fence.py"], check=True)


@pytest.mark.parametrize("plant", ["none", "status_json", "wrong_gate_shape", "invalid_json", "scalar_json"])
def test_governance_gate_data_command(tmp_path, plant):
    files = {"governance/generators.json": json.dumps({"uv.lock": {
        "command": "uv lock", "tool": "uv==0.13.1", "inputs": ["pyproject.toml"]}})}
    if plant == "status_json":
        files["governance/STATUS.json"] = '{"status": "Synthetic process document"}'
    if plant != "none" and plant != "status_json":
        files["governance/generators.json"] = {
            "wrong_gate_shape": '{"status": "Synthetic process document"}',
            "invalid_json": "invalid", "scalar_json": '"prose"'}[plant]
    for name, text in files.items():
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())],
                            cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == int(plant != "none"), result.stderr
