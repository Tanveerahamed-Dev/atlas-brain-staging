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
GOVERNANCE = {"governance/generators.json", "governance/review.schema.json", "governance/review-policy.json"}
DYNAMIC = {"exec", "eval", "compile", "__builtins__", "builtins.exec", "builtins.eval", "builtins.compile", "builtins.__dict__"}


def allowed(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(p.lower() in DENIED or PROCESS.search(p.lower()) for p in parts):
        return False
    if path.startswith("governance/"):
        return path in GOVERNANCE
    return path in ROOTS or path.startswith(TREES)


def dependencies_allowed(config: dict) -> bool:
    project = config.get("project", {})
    extras = project.get("optional-dependencies", {})
    return project.get("dependencies") == [] and isinstance(extras, dict) and all(v == [] for v in extras.values())


def gate_data_allowed(path: str, data) -> bool:
    if not isinstance(data, dict):
        return False
    if path == "governance/generators.json":
        return bool(data) and all(
            isinstance(spec, dict) and set(spec) == {"command", "tool", "inputs"}
            and all(isinstance(spec[k], str) and spec[k] for k in ("command", "tool"))
            and isinstance(spec["inputs"], list) and spec["inputs"]
            and all(isinstance(item, str) and item for item in spec["inputs"])
            for spec in data.values()
        )
    if path == "governance/review.schema.json":
        return (data.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
                and data.get("type") == "object" and isinstance(data.get("properties"), dict)
                and isinstance(data.get("required"), list))
    if path == "governance/review-policy.json":
        return (set(data) == {"decision", "same_family_pairs", "unsigned_bootstrap"}
                and isinstance(data["decision"], str) and bool(data["decision"])
                and type(data["unsigned_bootstrap"]) is bool and isinstance(data["same_family_pairs"], list)
                and all(isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, str) and x for x in pair)
                        for pair in data["same_family_pairs"]))
    return False


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
        if isinstance(node, (ast.Name, ast.Attribute)) and qualified(node) in DYNAMIC:
            return False
        if isinstance(node, ast.Call) and qualified(node.func) in {"getattr", "vars", "builtins.getattr", "builtins.vars"} and node.args and qualified(node.args[0]) == "builtins":
            return False
        if isinstance(node, ast.Call) and qualified(node.func) in {"__import__", "builtins.__import__", "importlib.import_module"}:
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                return False
            modules.append(node.args[0].value)
    return all(
        name not in DYNAMIC and name.split(".")[0] in sys.stdlib_module_names | {"atlas_brain"}
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
                failures += not gate_data_allowed(path, json.loads(Path(path).read_text(encoding="utf-8")))
        failures += not dependencies_allowed(tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8")))
    except (OSError, ValueError, SyntaxError, TypeError):
        failures = 1
    print(f"scope fence: {failures} refused paths, imports, dependencies or machine-data files")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
