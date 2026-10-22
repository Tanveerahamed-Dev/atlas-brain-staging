"""Syntax contexts have explicit domains and never turn missing entries into proof."""
import ast
import inspect

import pytest

from atlas_brain.kernel import lints, token_lints


def test_parent_domain_is_complete_and_the_module_root_is_explicit():
    construct = getattr(lints, 'parent_environment', None)
    assert construct is not None
    tree = ast.parse('def outer():\n def inner(): return value\n return inner()')
    parents = construct(tree)
    expected = {child: owner for owner in ast.walk(tree) for child in ast.iter_child_nodes(owner)}
    expected[tree] = tree
    assert parents == expected
    assert parents.keys() == set(ast.walk(tree))
    assert parents[tree] is tree


def test_parent_subscription_refuses_an_out_of_domain_node():
    lookup = getattr(lints, 'parent_value', None)
    assert lookup is not None
    tree = ast.parse('value')
    assert lookup(tree, {tree: tree}) is tree
    with pytest.raises(KeyError):
        lookup(ast.Name(id='other'), {tree: tree})


def test_successor_subscription_distinguishes_empty_from_missing():
    lookup = getattr(token_lints, 'successor_value', None)
    assert lookup is not None
    tree = ast.parse('first()\nsecond()')
    first, second = tree.body
    assert lookup(first, {first: (second,)}) == (second,)
    assert lookup(second, {second: ()}) == ()
    with pytest.raises(KeyError):
        lookup(ast.Name(id='other'), {second: ()})


def test_successor_consumer_source_has_no_missing_key_default():
    source = inspect.getsource(token_lints.fallback_nodes)
    assert not tuple(item for item in lints.lint(source, 'atlas_brain/kernel/probe.py') if item[0] == 3)


@pytest.mark.parametrize('source,refused', [
    ('def verdict():\n return CheckResult()', False),
    ('def other():\n return CheckResult()', True),
    ('class Worker:\n def verdict(self):\n  return CheckResult()', True),
    ('def verdict():\n def inner():\n  return CheckResult()', False),
    ('CheckResult()', True),
])
def test_public_verdict_scope_keeps_the_existing_module_function_boundary(source, refused):
    assert any(rule == 4 for rule, _ in lints.lint(source, 'atlas_brain/kernel/verdict.py')) is refused


def test_public_scanner_refuses_a_corrupted_parent_domain(monkeypatch):
    monkeypatch.setattr(lints, 'parent_environment', lambda tree: {}, raising=False)
    with pytest.raises(KeyError):
        lints.lint('factory(value)', 'atlas_brain/kernel/probe.py')
