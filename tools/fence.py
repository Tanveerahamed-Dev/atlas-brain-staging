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
# S3 3.3.1: dynamic importing requires an approved exact pack-loader path; none exists yet.
BANNED = ("tkinter", "curses", "webbrowser", "http.server", "wsgiref", "socketserver", "importlib", "builtins")
GOVERNANCE = {"governance/generators.json", "governance/review.schema.json", "governance/review-policy.json"}
DYNAMIC = {"exec", "eval", "compile", "__import__", "__builtins__", "globals", "locals", "vars",
           "getattr", "setattr", "delattr", "hasattr", "dir",
           "help", "breakpoint", "__loader__", "__spec__",
           "builtins.exec", "builtins.eval", "builtins.compile", "builtins.__import__", "sys.modules", "sys._getframe"}
CODE_ATTRIBUTES = {"__globals__", "__builtins__", "__code__", "__closure__", "__dict__", "__subclasses__",
                   "f_builtins", "f_globals", "f_locals", "gi_frame", "cr_frame", "ag_frame", "tb_frame"}
# ADR-0002: changes require an amendment, REV verdict and supervisor approval.
STDLIB_API = {
    "collections.abc.Mapping", "dataclasses.asdict", "dataclasses.dataclass", "enum.StrEnum",
    "hashlib.sha256", "json.dumps", "json.loads", "math.isfinite", "stat.S_ISDIR", "stat.S_ISREG",
    "pathlib.Path", "pathlib.PurePosixPath", "re.ASCII", "re.Pattern", "re.compile", "re.error",
    "re.fullmatch", "re.search", "typing.Literal", "typing.NewType", "typing.final", "typing.cast",
}
# ADR-0003 amends ADR-0002: exact AST endpoints at their actual using paths.
SCOPED_API = {
    "atlas_brain/kernel/token_lints.py": {
        "ast.AST", "ast.Attribute", "ast.Call", "ast.If", "ast.IfExp", "ast.Match", "ast.MatchClass",
        "ast.MatchOr", "ast.MatchSingleton", "ast.MatchValue", "ast.Name", "ast.pattern", "ast.walk",
    },
    "atlas_brain/kernel/lints.py": {
        "ast.AnnAssign", "ast.arg", "ast.Assign", "ast.AST", "ast.AsyncFor", "ast.AsyncFunctionDef",
        "ast.Attribute", "ast.BinOp", "ast.BitOr", "ast.Call", "ast.ClassDef", "ast.comprehension",
        "ast.Constant", "ast.ExceptHandler", "ast.expr", "ast.For", "ast.FunctionDef", "ast.Import",
        "ast.ImportFrom", "ast.iter_child_nodes", "ast.Lambda", "ast.Load", "ast.Module", "ast.Name",
        "ast.NamedExpr", "ast.parse", "ast.Set", "ast.SetComp", "ast.stmt", "ast.Store", "ast.Subscript", "ast.walk",
    },
}


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


def import_bindings(tree, path):
    aliases, exports, declarations = {}, {}, set()
    def walk(node, scope=""):
        pairs = []
        if isinstance(node, ast.Import):
            for item in node.names:
                pairs.append((item.asname or item.name.split(".")[0], item.name if item.asname else item.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if any(item.name == "*" for item in node.names):
                raise ValueError("wildcard import has no closed provenance")
            base = node.module or ""
            if node.level:
                anchor = PurePosixPath(path).parent.parts
                if node.level >= len(anchor) + 1:
                    raise ValueError("relative import leaves engine")
                base = ".".join((*anchor[:len(anchor) - node.level + 1], *([base] if base else [])))
            pairs = [(item.asname or item.name, f"{base}.{item.name}") for item in node.names]
        for name, target in pairs:
            if name in aliases and aliases[name] != target:
                raise ValueError("ambiguous import binding")
            aliases[name], exports[scope + name] = target, target
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            declarations.add(scope + node.name)
            scope += node.name + "."
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            declarations.add(scope + node.id)
        for child in ast.iter_child_nodes(node):
            walk(child, scope)
    walk(tree)
    return aliases, exports, declarations


class ImportIndex:
    def __init__(self, sources, forbidden=()):
        self.modules = {}
        self.forbidden = frozenset(forbidden)
        packages = set()
        for path, source in sources.items():
            module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
            if module in self.modules:
                raise ValueError("ambiguous engine module")
            self.modules[module] = import_bindings(ast.parse(source), path)[1:]
            if path.endswith("/__init__.py"):
                packages.add(module)
        for module, (exports, declarations) in self.modules.items():
            if module not in packages and any(m.startswith(module + ".") for m in self.modules):
                raise ValueError("non-package module has descendants")
            if any(self.namespace(module + "." + key) and target != module + "." + key for key, target in exports.items()):
                raise ValueError("ambiguous imported module export")
            if any(self.namespace(module + "." + key) for key in declarations):
                raise ValueError("ambiguous declared module export")

    def namespace(self, name):
        return name in self.modules or any(module.startswith(name + ".") for module in self.modules)

    def origin(self, name, seen=frozenset()):
        if any(name == module or name.startswith(module + ".") for module in self.forbidden):
            return None
        if not name.startswith("atlas_brain.") and name != "atlas_brain":
            return name
        if name in seen:
            return None
        if self.namespace(name):
            return name
        module = max((m for m in self.modules if name.startswith(m + ".")), key=len, default="")
        if not module:
            return None
        exports, declarations = self.modules[module]
        tail = name[len(module) + 1:]
        binding = max((key for key in exports if tail == key or tail.startswith(key + ".")), key=len, default="")
        if binding:
            return self.origin(exports[binding] + tail[len(binding):], seen | {name})
        return name if any(tail == key or tail.startswith(key + ".") for key in declarations) else None


def source_allowed(source: str, sources=None, path="atlas_brain/probe.py") -> bool:
    tree = ast.parse(source)
    apis = STDLIB_API | SCOPED_API.get(path, set())
    scoped_modules = {p.removesuffix(".py").replace("/", ".") for p in SCOPED_API}
    try:
        aliases = import_bindings(tree, path)[0]
        index = ImportIndex(sources or {}, () if path in SCOPED_API else scoped_modules)
    except ValueError:
        return False
    def admitted(name):
        if name is None or (path not in SCOPED_API and any(name == m or name.startswith(m + ".") for m in scoped_modules)):
            return False
        return (index.namespace(name) or name.startswith("atlas_brain.") or name in apis
                                     or any(api.startswith(name + ".") for api in apis))
    if not all(admitted(index.origin(name)) for name in aliases.values()):
        return False
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, "")
        base = qualified(node.value) if isinstance(node, ast.Attribute) else ""
        return base + "." + node.attr if base else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and (node.attr in CODE_ATTRIBUTES
                or node.attr.startswith("_") and node.attr not in {"__init__", "__init_subclass__"}):
            return False
        if isinstance(node, ast.Name) and node.id in DYNAMIC:
            return False
        if isinstance(node, (ast.Name, ast.Attribute)):
            raw = qualified(node)
            if not raw:
                continue
            name = index.origin(raw)
            if not admitted(name):
                return False
            if index.namespace(name) or any(api.startswith(name + ".") for api in apis):
                parent = parents.get(node)
                if not isinstance(parent, ast.Attribute) or parent.value is not node:
                    return False
    return True


def main() -> int:
    paths = sys.argv[1:] or subprocess.check_output(
        ["git", "ls-files", "-z"],
    ).decode("utf-8").rstrip("\0").split("\0")
    try:
        failures = sum(not allowed(path) for path in paths)
        sources = {}
        for path in paths:
            if path.startswith("atlas_brain/") and path.endswith(".py"):
                if Path(path).is_symlink():
                    raise ValueError("engine source link refused")
                sources[path] = Path(path).read_text(encoding="utf-8")
        failures += sum(not source_allowed(source, sources, path) for path, source in sources.items())
        for path in paths:
            if path.startswith("governance/") and allowed(path):
                failures += not gate_data_allowed(path, json.loads(Path(path).read_text(encoding="utf-8")))
        failures += not dependencies_allowed(tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8")))
    except (OSError, ValueError, SyntaxError, TypeError):
        failures = 1
    print(f"scope fence: {failures} refused paths, imports, dependencies or machine-data files")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
