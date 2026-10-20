import subprocess
import sys

import pytest

from tools.fence import allowed


@pytest.mark.parametrize("path", [
    "outside.txt", "prompts/x.md", "tools/prompts/x.md", "docs/adr/BOARD.md",
    "tools/agent-notes.md", "tests/AGENTS.md", "tools/CLAUDE.md",
    "tools/.claude/x", "tools/.codex/x", "tools/.agents/x", "tools/.mcp.json",
    "tools/.specify/x", "tools/specs/x", "tools/plans/x", "docs/other.md",
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
