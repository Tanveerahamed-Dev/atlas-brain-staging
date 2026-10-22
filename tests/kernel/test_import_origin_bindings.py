"""Nested import origins must not certify a different global callable or class."""
import ast
from typing import Any

import pytest

from atlas_brain.kernel.lints import binding_environment
from atlas_brain.kernel.token_lints import binding_proof, fallback_nodes


CASES = [
    ('unknown', 'from builtins import str as U',
     'from atlas_brain.kernel.states import Unknown as U',
     'STATES = {"known": "up"}\ndef mapped(raw):\n if raw not in STATES: return U("up")\n return STATES[raw]',
     'atlas_brain.kernel.states.Unknown', 'calls'),
    ('assertion', 'from builtins import str as terminal',
     'from typing import assert_never as terminal',
     'def mapped(raw):\n match raw:\n  case "known": return "up"\n  case _ as missing: terminal(missing)\n return "up"',
     'typing.assert_never', 'calls'),
    ('fact', 'from builtins import str as K\nfrom typing import assert_never as terminal',
     'from atlas_brain.kernel.states import Known as K',
     'def mapped(raw):\n match raw:\n  case K(): return "up"\n  case _ as missing: terminal(missing)',
     'typing.assert_never', 'facts'),
]


@pytest.mark.parametrize('scope', ['def local():', 'class Local:'])
@pytest.mark.parametrize('label,prefix,inner,body,target,kind', CASES)
def test_nested_import_cannot_certify_a_different_global_origin(scope, label, prefix, inner, body, target, kind):
    source = prefix + '\n' + scope + '\n ' + inner + '\n' + body
    namespace: dict[str, Any] = {}
    exec(source, namespace)
    assert namespace['mapped']('mystery') == 'up'  # The planted program manufactures health.
    tree = ast.parse(source)
    aliases, rebound = binding_environment(tree)
    calls, facts = binding_proof(tree, aliases, rebound, call_target=target)
    witnesses = calls if kind == 'calls' else facts
    guard = next(node for node in ast.walk(tree) if isinstance(node, (ast.If, ast.Match)))
    assert (len(witnesses), guard in fallback_nodes(tree, aliases, rebound)) == (0, True)


@pytest.mark.parametrize('source,expected', [
    ('from typing import assert_never as terminal\ndef local():\n from typing import assert_never as terminal\nterminal(value)', 1),
    ('from typing import assert_never as first\nfrom typing import assert_never as second\nfirst(value)\nsecond(value)', 2),
    ('from typing import assert_never as terminal\nfrom builtins import str as local\ndef helper():\n from builtins import int as local\nterminal(value)', 1),
])
def test_repeated_origins_and_unrelated_import_conflicts_preserve_genuine_calls(source, expected):
    tree = ast.parse(source)
    calls, _ = binding_proof(tree, *binding_environment(tree))
    assert len(calls) == expected
