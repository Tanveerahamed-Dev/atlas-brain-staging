"""Token fallback guards: planted violations plus the real implementation."""
import inspect
import textwrap

import pytest

from atlas_brain.evidence.parsekit.rules import TokenMap
from atlas_brain.evidence.parsekit.token_lint import lint_token_handler


@pytest.mark.parametrize("source", [
    "def map(token): return rows.get(token, 'full')",
    "def map(token): return rows.setdefault(token, 'full')",
    "def map(token): return 'half' in token",
    "def map(token): return token.startswith('half')",
    "def map(token):\n if token == 'half': return 'half'\n else: return 'full'",
    "def map(token): return 'half' if token == 'half' else 'full'",
    "def map(token):\n match token:\n  case _: return 'full'",
    "def map(token):\n try: return rows[token]\n except KeyError: return 'full'",
])
def test_planted_token_fallbacks_are_refused(source):
    assert lint_token_handler(source)


def test_real_closed_handler_has_no_default_or_substring_mapping():
    assert lint_token_handler(textwrap.dedent(inspect.getsource(TokenMap.resolve))) == ()


def test_explicit_unknown_branch_is_admitted():
    source = "def map(token):\n if token == 'half': return 'half'\n else: return Unknown()"
    assert lint_token_handler(source) == ()


def test_token_map_refuses_subclasses():
    with pytest.raises(TypeError):
        type("FallbackMap", (TokenMap,), {})
