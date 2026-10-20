"""Tracked-path fence; explicit arguments support planted violation probes."""
import re
import subprocess
import sys
from pathlib import PurePosixPath

ROOTS = {"README.md", "LICENSE", ".gitattributes", ".gitignore",
         "pyproject.toml", "uv.lock", ".python-version"}
TREES = ("atlas_brain/", "tests/", "fixtures/", "docs/adr/", "docs/contract/",
         "tools/", "governance/", ".github/")
DENIED = {"plans", "prompts", "agents.md", "claude.md", ".claude", ".codex",
          ".agents", ".mcp.json", ".specify", "specs"}
PROCESS = re.compile(r"(?:^|[-_.])(boards?|agent[-_]?notes?)(?:$|[-_.])", re.ASCII)


def allowed(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(p.lower() in DENIED or PROCESS.search(p.lower()) for p in parts):
        return False
    return path in ROOTS or path.startswith(TREES)


def main() -> int:
    paths = sys.argv[1:] or subprocess.check_output(
        ["git", "ls-files", "-z"],
    ).decode("utf-8").rstrip("\0").split("\0")
    failures = sum(not allowed(path) for path in paths)
    print(f"path fence: {failures} refused paths")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
