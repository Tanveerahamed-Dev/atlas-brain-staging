import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import allowed, dependencies_allowed, source_allowed


@pytest.mark.parametrize("path", [
    "outside.txt", "prompts/x.md", "tools/prompts/x.md", "docs/adr/BOARD.md",
    "tools/agent-notes.md", "tests/AGENTS.md", "tools/CLAUDE.md",
    "tools/.claude/x", "tools/.codex/x", "tools/.agents/x", "tools/.mcp.json",
    "tools/.specify/x", "tools/specs/x", "tools/plans/x", "docs/other.md",
    "governance/STATUS.md", "governance/notes.txt", "governance/nested/readme.md",
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


@pytest.mark.parametrize("source", [
    "import webbrowser", "import tkinter.ttk", "from http import server",
    "from http.server import HTTPServer", "import curses", "import wsgiref",
    "import socketserver", "__import__('webbrowser')",
    "from importlib import import_module as load; load('http.server')",
    "__import__(module_name)", "import unapproved_third_party",
])
def test_denied_engine_imports(source):
    assert not source_allowed(source)


@pytest.mark.parametrize("source", ["import json", "from typing import Literal", "from atlas_brain.kernel import states"])
def test_allowed_engine_imports(source):
    assert source_allowed(source)


@pytest.mark.parametrize("config", [
    {"project": {"dependencies": ["unapproved==1.0"]}},
    {"project": {"dependencies": [], "optional-dependencies": {"extra": ["unapproved"]}}},
])
def test_runtime_dependency_allowlist(config):
    assert not dependencies_allowed(config)


def test_empty_runtime_dependencies_pass():
    assert dependencies_allowed({"project": {"dependencies": []}})


@pytest.mark.parametrize("plant", ["none", "import", "dependency", "prose", "invalid_json", "scalar_json"])
def test_required_fence_command_refuses_real_tracked_plants(tmp_path, plant):
    source = "import webbrowser" if plant == "import" else "import json"
    deps = '["unapproved==1.0"]' if plant == "dependency" else "[]"
    files = {"pyproject.toml": f"[project]\ndependencies = {deps}\n",
             "atlas_brain/probe.py": source, "governance/probe.json": "{}"}
    if plant == "prose":
        files["governance/STATUS.md"] = "Synthetic process document."
    if plant in {"invalid_json", "scalar_json"}:
        files["governance/probe.json"] = "invalid" if plant == "invalid_json" else '"prose"'
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == int(plant != "none"), result.stderr
