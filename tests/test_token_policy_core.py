"""Token policy plants run through the guard before source-census activation."""
import pytest

from atlas_brain.evidence.parsekit.token_lint import lint_token_handler


@pytest.mark.parametrize("source", [
    "def decode(field):\n token = field.raw\n lookup = rows.get\n return lookup(token, 'full')\n",
    "def decode(field): return field.raw[:4] == 'half'\n",
    "def decode(field):\n rows = {'half': 'half'}\n return rows.pop(field.raw, 'full')\n",
    "def decode(field):\n lookup = rows.pop\n return lookup(field.raw, 'full')\n",
    "def decode(field): return dict.pop(rows, field.raw, 'full')\n",
    "def decode(field): return mapper(field.raw, 'full')\n",
    "def decode(token: bytes): return token[:4]\n",
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
def test_structural_token_policy_refuses_every_planted_escape(source):
    assert lint_token_handler(source, structural=True)

@pytest.mark.parametrize("source", [
    "def decode(field): return TABLE.resolve(field)\n",
    "def decode(field): return exact(field.raw)\n",
    "def metadata():\n text = 'status'\n return Unknown()\ndef decode(field):\n text = field.raw\n return Known(value=text, basis=Basis.OBSERVED, raw=text)\n",
    "TABLE = TokenMap.closed({'week': Unit.WEEK})\nPATTERN = compile_pattern(r'(?P<value>\\S++)')\ndef decode(raw: bytes, span, capture):\n part = raw[0:4]\n matched = PATTERN.fullmatch(part)\n if matched is None: return Unknown()\n text = matched['value'].decode('ascii')\n item = Captured(text, span, text)\n resolved = TABLE.resolve(item, capture)\n return resolved.value\n",
    "def decode(field): return Unknown(reason=UnknownReason.PARSE_PARTIAL, detail=field.raw, evidence=(), candidates=(), next_evidence=())\n",
    "def decode(field): return Known(value=field.raw, basis=Basis.OBSERVED, raw=field.raw)\n",
])
def test_structural_token_policy_positive_controls(source):
    assert lint_token_handler(source, structural=True) == ()
