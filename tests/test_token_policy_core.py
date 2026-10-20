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
    "def decode(field): return Known(value=field.raw, basis=Basis.OBSERVED, raw=field.raw)\n",
])
def test_structural_token_policy_positive_controls(source):
    assert lint_token_handler(source, structural=True) == ()
