"""Pure type syntax is distinct from executable value and default expressions."""
import pytest

from atlas_brain.kernel.lints import lint


@pytest.mark.parametrize('prefix,statement', [
    ('', 'pending: list[object] = []'),
    ('import ast', 'pending: set[ast.AST] = set()'),
    ('import ast as nodes', 'pending: set[nodes.AST] = set()'),
    ('from ast import AST as Node', 'pending: set[Node] = set()'),
    ('from builtins import set as S\nfrom ast import AST as Node', 'pending: S[Node] = S()'),
    ('', 'def helper(arg: list[object]): return arg'),
    ('', 'def helper() -> list[object]: return value'),
    ('from typing import cast\nimport ast', 'pending = cast(list[ast.AST], value)'),
])
def test_proven_type_annotations_are_not_value_lookups(prefix, statement):
    source = prefix + '\ndef inspect(value, ready):\n if ready:\n  ' + statement + '\n  return value\n return ()'
    assert 3 not in {rule for rule, _ in lint(source, 'atlas_brain/kernel/example.py')}


@pytest.mark.parametrize('prefix,statement', [
    ('', 'pending: mapping[raw] = ()'),
    ('', 'pending: (states[raw] if raw in states else "up") = ()'),
    ('', 'pending: list[mapping[raw]] = ()'),
    ('', 'pending: list[object] = mapping[raw]'),
    ('', 'def helper(arg: list[object] = mapping[raw]): return arg'),
    ('import ast\nast.AST = replacement', 'pending: set[ast.AST] = set()'),
    ('from ast import AST as Node\nNode = replacement', 'pending: set[Node] = set()'),
    ('from other import AST as Node', 'pending: set[Node] = set()'),
])
def test_annotations_cannot_hide_runtime_or_unproved_lookups(prefix, statement):
    source = prefix + '\ndef inspect(value, ready):\n if ready:\n  ' + statement + '\n  return value\n return ()'
    target_line = next(index for index, text in enumerate(source.splitlines(), 1) if text.strip() == statement)
    assert (3, target_line) in lint(source, 'atlas_brain/kernel/example.py')


def test_pattern_capture_cannot_certify_an_ast_type_annotation():
    source = ('from ast import AST as Node\nmatch value:\n case {"type": Node}: pass\n'
              'def inspect(value, ready):\n if ready:\n  pending: set[Node] = set()\n return ()')
    assert (3, 6) in lint(source, 'atlas_brain/kernel/example.py')
