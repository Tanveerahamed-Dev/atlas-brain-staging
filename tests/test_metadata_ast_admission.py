"""Exact syntax-inspection admission; the K consumer is parsed, never executed."""
import ast
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

USING = "atlas_brain/kernel/metadata_readonly.py"
REVISION = "fe80965472ab447f789b60522f79603adc5a876d"
BLOB = "4b9fa0eb989dd47bd1f4a68a9e7dd4c1342cbcbf"
DIGEST = "8cde05ea2897a8e68d41ec5157e3ba7f247f3a86d176a50cda50fc7c32a0135a"
APIS = {
    "ast.AST", "ast.AnnAssign", "ast.Assign", "ast.AsyncFunctionDef", "ast.AsyncWith",
    "ast.Attribute", "ast.Call", "ast.ClassDef", "ast.Dict", "ast.DictComp", "ast.ExceptHandler",
    "ast.FunctionDef", "ast.Global", "ast.Import", "ast.ImportFrom", "ast.Lambda", "ast.List",
    "ast.ListComp", "ast.Load", "ast.Match", "ast.Name", "ast.Nonlocal", "ast.Return", "ast.Set",
    "ast.SetComp", "ast.Subscript", "ast.With", "ast.Yield", "ast.YieldFrom",
    "ast.iter_child_nodes", "ast.walk",
}


@pytest.fixture(scope="module")
def actual_source():
    endpoint = "repos/Tanveerahamed-Dev/atlas-brain-staging"
    entry = json.loads(subprocess.check_output([
        "gh", "api", f"{endpoint}/contents/{USING}?ref={REVISION}",
    ], encoding="utf-8"))
    assert entry["sha"] == BLOB and entry["encoding"] == "base64"
    payload = base64.b64decode(entry["content"])
    assert hashlib.sha256(payload).hexdigest() == DIGEST
    return payload.decode("utf-8")


def test_actual_pinned_source_uses_exactly_the_admitted_endpoints(actual_source):
    tree = ast.parse(actual_source)
    used = {"ast." + node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "ast"}
    assert used == APIS == SCOPED_API[USING] and len(APIS) == 31
    assert len(actual_source.splitlines()) == 172
    # Strings in PURE_CALLS describe inspected source; they do not import those APIs.
    assert "ast.parse" not in used and "ast.iter_fields" not in used
    assert source_allowed(actual_source, path=USING)


def test_amendment_and_prior_admissions_are_exact():
    text = Path("docs/adr/0011-adr0002-metadata-ast.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == APIS
    assert len(text.splitlines()) <= 60 and len(text) <= 4000
    assert len(STDLIB_API) == 22 and not APIS & STDLIB_API
    assert [len(SCOPED_API[path]) for path in (
        "atlas_brain/kernel/token_lints.py", "atlas_brain/kernel/lints.py",
        "atlas_brain/evidence/parsekit/token_lint.py", "atlas_brain/evidence/parsekit/token_audit.py",
    )] == [29, 32, 34, 10]
    assert set(RUNTIME_API) == {"atlas_brain/evidence/admission.py", "atlas_brain/evidence/archives.py"}
    assert [len(RUNTIME_API[path]) for path in sorted(RUNTIME_API)] == [2, 10]


def test_every_unlisted_ast_export_remains_refused():
    for name in sorted(vars(ast)):
        if name.isidentifier() and "ast." + name not in APIS:
            assert not source_allowed(f"from ast import {name}", path=USING), name
    assert not source_allowed("import ast; ast.literal_eval('0')", path=USING)
    assert not source_allowed("from ast import *", path=USING)


@pytest.mark.parametrize("api", sorted(APIS))
def test_exact_uses_do_not_grant_other_files_or_reexports(api):
    assert source_allowed(f"import ast; {api}", path=USING)
    assert source_allowed(f"from ast import {api[4:]} as value; value", path=USING)
    for path in ("atlas_brain/kernel/runtime.py", "atlas_brain/kernel/metadata_reader.py",
                 USING + "/extra.py", "tools/metadata_readonly.py"):
        assert not source_allowed(f"import ast; {api}", path=path)
    sources = {USING: f"import ast\nexported = {api}\ndef reader(node): return False",
               "atlas_brain/bridge.py": "from .kernel.metadata_readonly import exported"}
    for consumer in ("from .kernel.metadata_readonly import exported; exported",
                     "from .kernel import metadata_readonly; metadata_readonly.exported",
                     "from .bridge import exported; exported"):
        assert not source_allowed(consumer, sources, "atlas_brain/runtime.py")
    assert not source_allowed("from .kernel.metadata_readonly import reader", sources, "atlas_brain/runtime.py")


def test_actual_tracked_cli_keeps_source_and_paired_refusals(tmp_path, actual_source):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(actual_source, encoding="utf-8", newline="\n")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())

    def check(expected, path):
        result = subprocess.run([sys.executable, tool], cwd=tmp_path,
                                capture_output=True, text=True, check=False)
        assert result.returncode == expected, result.stdout + result.stderr
        assert ("scope fence: 1 refused" if expected else "scope fence: 0 refused") in result.stdout
        if expected:
            assert path in result.stdout
        return result.stdout

    check(0, USING)
    using.write_text(actual_source + "\nast.literal_eval('0')\n", encoding="utf-8")
    assert "ast.literal_eval" in check(1, USING)
    using.write_text(actual_source, encoding="utf-8", newline="\n")
    outside = tmp_path / "atlas_brain/runtime.py"
    outside.write_text("import ast\n" + "\n".join(sorted(APIS)) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    output = check(1, "atlas_brain/runtime.py")
    assert all(api in output for api in APIS)
    outside.write_text("from .kernel.metadata_readonly import readonly_functions\n", encoding="utf-8")
    check(1, "atlas_brain/runtime.py")
