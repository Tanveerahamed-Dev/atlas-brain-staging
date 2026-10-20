"""Required source census plus planted foreign-pack and coverage failures."""
from pathlib import Path

import pytest

from atlas_brain.evidence.parsekit.token_audit import SourceVisitor, audit_tree


def test_owned_token_policy_gate():
    report = audit_tree(Path("atlas_brain"))
    assert report.expected and report.expected == report.audited
    assert report.findings == ()


def _tree(tmp_path, source):
    core = tmp_path / "evidence/parsekit/rules.py"
    core.parent.mkdir(parents=True)
    core.write_text("class TokenMap:\n def resolve(self, value): return Unknown()\n", encoding="utf-8")
    foreign = tmp_path / "packs/new/parsers/fields.py"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("raise AssertionError('source must not execute')\n" + source, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("source", [
    "def decode(field):\n token = field.raw\n lookup = rows.get\n return lookup(token, 'full')\n",
    "def decode(field): return field.raw[:4] == 'half'\n",
])
def test_foreign_pack_violation_is_discovered_without_registration(tmp_path, source):
    report = audit_tree(_tree(tmp_path, source))
    assert report.findings
    assert any("packs/new/parsers/fields.py" in path for path, _, _ in report.findings)


def test_foreign_safe_lookup_is_scanned_without_importing_it(tmp_path):
    report = audit_tree(_tree(tmp_path, "def decode(field): return TABLE.resolve(field)\n"))
    assert report.expected == report.audited and report.findings == ()


def test_missing_scan_of_an_expected_handler_refuses_gate(tmp_path, monkeypatch):
    root = _tree(tmp_path, "async def decode(field): return TABLE.resolve(field)\n")
    monkeypatch.setattr(SourceVisitor, "visit_AsyncFunctionDef", lambda self, node: None)
    with pytest.raises(ValueError, match="unscanned"):
        audit_tree(root)


def test_module_named_function_has_its_own_scan_record(tmp_path):
    root = _tree(tmp_path, "")
    (root / "packs/new/parsers/fields.py").write_text(
        "def module(field): return TABLE.resolve(field)\n", encoding="utf-8",
    )
    report = audit_tree(root)
    assert report.expected == report.audited and report.findings == ()
