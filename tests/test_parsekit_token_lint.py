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


@pytest.mark.parametrize("source", [
    "def map(token, default='full'): return default",
    "def map(token, *, default='full'): return default",
    "def map(token):\n match token:\n  case value: return value",
])
def test_parameter_and_pattern_defaults_are_refused(source):
    assert lint_token_handler(source)


def test_explicit_raise_is_admitted_and_diagnostics_are_stable():
    source = "def map(token):\n if token == 'half': return 'half'\n else: raise ValueError()"
    assert lint_token_handler(source) == ()
    assert lint_token_handler("def map(token): return rows.get(token, 0)") == (
        (1, "token_convenience_lookup"),
    )


def test_rule_engine_rejects_a_foreign_fallback_resolver_before_calling_it():
    from typing import cast

    from atlas_brain.evidence.parsekit.rules import Rule, run_rules
    from atlas_brain.kernel.states import CaptureId

    class FallbackMap:
        def resolve(self, field, capture):
            raise AssertionError("foreign resolver was executed")

    rule = Rule("value", "start", r"duplex (?P<duplex>\S++)", "record", "start", "", ("duplex",))
    with pytest.raises(ValueError):
        run_rules(b"duplex a-half\n", CaptureId("cap-a"), (rule,),
                  (("duplex", cast(TokenMap, FallbackMap())),))


@pytest.mark.parametrize("source", [
    "def map(token): return 'full'",
    "def map(token):\n if token == 'half': return 'half'\n return 'full'",
    "def map(token):\n if token == 'half': return 'half'\n fallback = 'full'\n return fallback",
])
def test_implicit_fallthrough_token_defaults_are_refused(source):
    assert lint_token_handler(source)


def test_explicit_unknown_fallthrough_and_exact_lookup_are_admitted():
    source = "def map(token):\n if token == 'half': return 'half'\n return Unknown()"
    assert lint_token_handler(source) == ()
    assert lint_token_handler("def map(token):\n rows = {'half': 1}\n return rows[token]") == ()
