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
    "def decode(field):\n rows = {'half': 'half'}\n return rows.pop(field.raw, 'full')\n",
    "def decode(field):\n lookup = rows.pop\n return lookup(field.raw, 'full')\n",
    "def decode(field): return dict.pop(rows, field.raw, 'full')\n",
    "def decode(field): return mapper(field.raw, 'full')\n",
    "PATTERN = compile_pattern(r'(?P<value>[A-Za-z]++)')\ndef decode(raw: bytes, evidence):\n original = raw\n if raw != b'full': raw = b'full'\n matched = PATTERN.fullmatch(raw)\n if matched is None: return Unknown()\n text = matched['value'].decode('ascii')\n return Known(value=text, basis=Basis.OBSERVED, evidence=evidence, raw=original.decode('ascii'))\n",
    "PATTERN = compile_pattern(r'(?P<value>[A-Za-z]++)')\ndef decode(raw: bytes):\n matched = PATTERN.fullmatch(raw)\n if matched is None: return Unknown()\n text = matched['value'].decode('ascii')\n return text.startswith('half')\n",
    "def decode(token: bytes): return token[:4]\n",
    "def reject(value) -> Unknown: return Known(value=bool(value), basis=Basis.OBSERVED, raw=value)\ndef decode(field): return reject(field.raw)\n",
    "def reject(reason, detail) -> Unknown: return Known(value=True)\ndef decode(field):\n text = field.raw\n if any(ord(char) < 32 for char in text): return reject(None, text)\n return Known(value=text, basis=Basis.OBSERVED, raw=text)\n",
    "def truth(x):\n return bool(x)\ndef decode(field, evidence): return Known(value=truth(field.raw), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def truth(x):\n return bool(x)\nconvert = truth\ndef decode(field, evidence): return Known(value=convert(field.raw), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def apply(fn, x): return fn(x)\ndef decode(field, evidence): return Known(value=apply(bool, field.raw), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def exact(token): return token\ndef decode(field, evidence):\n exact = truth\n return Known(value=exact(field.raw), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def decode(field, evidence): return Known(value=bool(field.raw), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "convert = bool\ndef decode(field, evidence):\n token = field.raw\n alias = convert\n return Known(value=alias(token), basis=Basis.OBSERVED, evidence=evidence, raw=token)\n",
    "def decode(field, evidence): return Known(value=bool(), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def decode(field, evidence): return Known(value=str(), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def decode(field, evidence): return Known(value=int(), basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "def decode(field, evidence):\n fallback = bool()\n return Known(value=fallback, basis=Basis.OBSERVED, evidence=evidence, raw=field.raw)\n",
    "class Defaults:\n healthy = 'full'\ndef decode(field):\n if field.raw not in ('half', 'full'): return Defaults.healthy\n return exact(field.raw)\n",
    "class Defaults:\n healthy = 'full'\ndef decode(field):\n fallback = Defaults.healthy\n return fallback\n",
    "class Defaults:\n healthy = 'full'\ndef decode(field): return Known(value=Defaults.healthy, basis=Basis.OBSERVED, raw=field.raw)\n",
    "class Defaults:\n raw = 'full'\ndef decode(field): return Defaults.raw\n",
    "def decode(field):\n token = field.raw\n if token not in ('half', 'full'): return 'fu' + 'll'\n return exact(token)\n",
    "def decode(field):\n token = field.raw\n if token not in ('half', 'full'): return str('fu' + 'll')\n return exact(token)\n",
    "def decode(field):\n token = field.raw\n if token not in ('half', 'full'): return '{}{}'.format('fu', 'll')\n return exact(token)\n",
    "def decode(field):\n token = field.raw\n return exact(token) or 'full'\n",
    "def decode(field):\n fallback: str = 'fu' + 'll'\n return fallback\n",
    "def decode(field):\n token = field.raw\n if token not in ('half', 'full'): return 'full'\n return exact(token)\n",
    "def decode(field):\n token = field.raw\n fallback: str = 'full'\n if token not in ('half', 'full'): return fallback\n return exact(token)\n",
    "def decode(field):\n token = field.raw\n fallback = 'full'\n if token not in ('half', 'full'): return fallback\n return exact(token)\n",
    "def decode(field):\n fallback = 'full'\n value = field.raw\n alias = value\n return mapper(alias, fallback)\n",
    "def decode(field): return mapper(*(field.raw, 'full'))\n",
    "def decode(field): return factory(field.raw, default='full')\n",
    "def decode(field):\n fallback = 'full'\n return Known(value=fallback, basis=Basis.OBSERVED, raw=field.raw)\n",
])
def test_foreign_pack_violation_is_discovered_without_registration(tmp_path, source):
    report = audit_tree(_tree(tmp_path, source))
    assert report.findings
    assert any("packs/new/parsers/fields.py" in path for path, _, _ in report.findings)


@pytest.mark.parametrize("source", [
    "def reject(reason, detail) -> Unknown: return Unknown(reason=reason, detail=detail)\ndef decode(field):\n text = field.raw\n if any(ord(char) < 32 for char in text): return reject(UnknownReason.PARSE_PARTIAL, text)\n reason = UnknownReason.CAPTURE_ERROR if text else UnknownReason.EMPTY_UNREGISTERED\n if not text: return reject(reason, text)\n return Known(value=text, basis=Basis.OBSERVED, raw=text)\n",
    "def decode(field): return TABLE.resolve(field)\n",
    "def exact(token): return token\ndef decode(field): return exact(field.raw)\n",
    "def metadata():\n text = 'status'\n return Unknown()\ndef decode(field):\n text = field.raw\n return Known(value=text, basis=Basis.OBSERVED, raw=text)\n",
    "TABLE = TokenMap.closed({'week': Unit.WEEK})\nPATTERN = compile_pattern(r'(?P<value>[A-Za-z]++)')\ndef decode(raw: bytes, span, capture):\n part = raw[0:4]\n matched = PATTERN.fullmatch(part)\n if matched is None: return Unknown()\n text = matched['value'].decode('ascii')\n item = Captured(text, span, text)\n resolved = TABLE.resolve(item, capture)\n return resolved.value\n",
    "def decode(field): return Unknown(reason=UnknownReason.PARSE_PARTIAL, detail=field.raw, evidence=(), candidates=(), next_evidence=())\n",
    "def decode(field): return Known(value=field.raw, basis=Basis.OBSERVED, raw=field.raw)\n",
])
def test_foreign_safe_lookup_is_scanned_without_importing_it(tmp_path, source):
    report = audit_tree(_tree(tmp_path, source))
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
