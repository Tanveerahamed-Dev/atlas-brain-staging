"""Tracked paths, standard-library runtime dependencies, and denied engine imports."""
import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

ROOTS = {"README.md", "LICENSE", ".gitattributes", ".gitignore",
         "pyproject.toml", "uv.lock", ".python-version"}
TREES = ("atlas_brain/", "tests/", "fixtures/", "docs/adr/", "docs/contract/",
         "tools/", "governance/", ".github/")
DENIED = {"plans", "prompts", "agents.md", "claude.md", ".claude", ".codex",
          ".agents", ".mcp.json", ".specify", "specs"}
PROCESS = re.compile(r"(?:^|[-_.])(boards?|agent[-_]?notes?)(?:$|[-_.])", re.ASCII)
BANNED = ("tkinter", "curses", "webbrowser", "http.server", "wsgiref", "socketserver")


def allowed(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(p.lower() in DENIED or PROCESS.search(p.lower()) for p in parts):
        return False
    if path.startswith("governance/") and PurePosixPath(path).suffix != ".json":
        return False
    return path in ROOTS or path.startswith(TREES)


def dependencies_allowed(config: dict) -> bool:
    project = config.get("project", {})
    extras = project.get("optional-dependencies", {})
    return project.get("dependencies") == [] and isinstance(extras, dict) and all(v == [] for v in extras.values())


def source_allowed(source: str) -> bool:
    tree, aliases, modules = ast.parse(source), {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                modules.append(item.name)
                aliases[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            modules.append(node.module or "")
            for item in node.names:
                qualified = f"{node.module}.{item.name}"
                modules.append(qualified)
                aliases[item.asname or item.name] = qualified
    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        return qualified(node.value) + "." + node.attr if isinstance(node, ast.Attribute) else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and qualified(node.func) in {"__import__", "builtins.__import__", "importlib.import_module"}:
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                return False
            modules.append(node.args[0].value)
    return all(
        name.split(".")[0] in sys.stdlib_module_names | {"atlas_brain"}
        and not any(name == banned or name.startswith(banned + ".") for banned in BANNED)
        for name in modules
    )


def main() -> int:
    paths = sys.argv[1:] or subprocess.check_output(
        ["git", "ls-files", "-z"],
    ).decode("utf-8").rstrip("\0").split("\0")
    try:
        failures = sum(not allowed(path) for path in paths)
        for path in paths:
            if path.startswith("atlas_brain/") and path.endswith(".py"):
                failures += not source_allowed(Path(path).read_text(encoding="utf-8"))
            if path.startswith("governance/") and allowed(path):
                failures += not isinstance(json.loads(Path(path).read_text(encoding="utf-8")), (dict, list))
        failures += not dependencies_allowed(tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8")))
    except (OSError, ValueError, SyntaxError, TypeError):
        failures = 1
    print(f"scope fence: {failures} refused paths, imports, dependencies or machine-data files")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
