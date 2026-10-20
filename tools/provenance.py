"""Fail-closed public-fixture provenance gate; see docs/contract/provenance.md."""
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


class InvalidProvenance(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidProvenance(message)


def parse(text):
    """Two-space block mappings; JSON double-quoted strings or ASCII tokens only."""
    root = {}
    stack = [root]
    for number, line in enumerate(text.split("\n"), 1):
        if not line:
            continue
        match = re.fullmatch(r"( *)([a-z][a-z0-9_]*):(?: (.+))?", line, re.ASCII)
        require(match is not None, f"line {number}: unsupported YAML syntax")
        spaces, key, raw = match.groups()
        depth = len(spaces) // 2
        require(len(spaces) % 2 == 0 and depth < len(stack), f"line {number}: invalid indentation")
        stack = stack[:depth + 1]
        parent = stack[-1]
        require(key not in parent, f"line {number}: duplicate key")
        if raw is None:
            value = {}
        elif raw.startswith('"'):
            value = json.loads(raw)
            require(isinstance(value, str), "scalar must be a string")
        else:
            require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", raw, re.ASCII) is not None,
                    f"line {number}: unsupported scalar")
            require(raw not in {"null", "true", "false"}, "reserved scalar")
            value = raw
        parent[key] = value
        if isinstance(value, dict):
            stack.append(value)
    return root


def fields(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys.split()), "missing or unknown fields")
    return value


def string(value):
    require(isinstance(value, str) and bool(value.strip()) and value == value.strip()
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "invalid or empty string")
    return value


def relative(value):
    value = string(value)
    require(not value.startswith("/") and "\\" not in value and ":" not in value
            and all(p not in {"", ".", ".."} for p in value.split("/")), "invalid relative path")
    return value


def record(path):
    data = fields(parse(path.read_bytes().decode("utf-8").replace("\r\n", "\n")),
                  "fixture_id file tier source platform licence sha256")
    require(re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)*", string(data["fixture_id"])), "invalid fixture id")
    name = relative(data["file"])
    require(len(PurePosixPath(name).parts) == 1 and name != "provenance.yaml", "file must be a sibling raw file")
    tier = string(data["tier"])
    require(tier in {"P", "S"}, "public M0 fixtures support P and S only; H/L are private, M needs witness support")
    source = fields(data["source"], "kind repository")
    require(source["kind"] == {"P": "library_testdata", "S": "synthetic"}[tier], "tier/kind mismatch")
    repo = fields(source["repository"], "url commit path")
    url = urlsplit(string(repo["url"]))
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment and url.path not in {"", "/"}, "invalid repository URL")
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", string(repo["commit"])), "commit must be a full hash")
    relative(repo["path"])
    platform = fields(data["platform"], "family model version version_basis")
    for value in platform.values():
        string(value)
    basis = platform["version_basis"]
    require(basis in {"unknown", "source_stated", "observed"}, "invalid version basis")
    values = [platform[k] for k in ("family", "model", "version")]
    require(all(v == "unstated" for v in values) if basis == "unknown"
            else all(v != "unstated" for v in values), "platform/version must be stated or explicitly unstated")
    require(tier != "P" or basis != "observed", "public samples use source_stated or unknown")
    licence = fields(data["licence"], "name redistribution notice")
    string(licence["name"])
    string(licence["notice"])
    require(licence["redistribution"] == "public", "raw bytes require public redistribution permission")
    digest = string(data["sha256"])
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid raw-byte SHA-256")
    raw = path.parent / name
    require(not raw.is_symlink() and raw.is_file(), "raw file missing or linked")
    require(hashlib.sha256(raw.read_bytes()).hexdigest() == digest, "raw-byte SHA-256 mismatch")
    return raw, data["fixture_id"]


def validate_tree(root):
    errors, covered, ids = [], set(), set()
    if root.is_symlink() or root.is_junction() or not root.is_dir():
        return ["fixture root missing, linked or not a directory"]
    entries, pending = [], [root]
    while pending:
        for entry in sorted(pending.pop().iterdir()):
            entries.append(entry)
            if entry.is_dir() and not entry.is_symlink() and not entry.is_junction():
                pending.append(entry)
    for entry in entries:
        label = entry.relative_to(root).as_posix()
        if entry.is_symlink() or entry.is_junction():
            errors.append(f"{label}: links are forbidden")
        elif entry.name == "provenance.yaml" and entry.is_file():
            try:
                raw, fixture_id = record(entry)
                require(fixture_id not in ids, "duplicate fixture id")
                ids.add(fixture_id)
                covered.add(raw)
            except (ValueError, OSError, RecursionError) as error:
                errors.append(f"{label}: {error}")
        elif not entry.is_dir() and not entry.is_file():
            errors.append(f"{label}: unsupported file type")
    for entry in entries:
        if entry.is_file() and entry.name != "provenance.yaml" and entry not in covered:
            errors.append(f"{entry.relative_to(root).as_posix()}: no valid provenance record")
    return errors


def main():
    explicit = len(sys.argv) > 1
    root = Path(sys.argv[1]) if explicit else Path("fixtures")
    try:
        errors = validate_tree(root) if explicit or root.exists() or root.is_symlink() else []
    except OSError as error:
        errors = [f"unreadable fixture tree: {error}"]
    for error in errors:
        print(error)
    print(f"provenance: {len(errors)} refusals")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
