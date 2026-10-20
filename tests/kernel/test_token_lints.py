import ast

import pytest

from atlas_brain.kernel.token_lints import fallback_node


@pytest.mark.parametrize('source', [
    'tokens.get(token, "up")',
    'tokens.get(token) or "up"',
    'tokens.get(token)',
    'tokens.setdefault(token, "up")',
    'tokens.setdefault(token)',
    'tokens.pop(token, "up")',
    'dict.pop(tokens, token, "up")',
    'defaultdict(lambda: "up")',
    'collections.defaultdict(lambda: "up")',
    '"up" if token not in tokens else tokens[token]',
    'if token in tokens:\n value = tokens[token]\nelse:\n value = "up"',
    'match token:\n case "up": value = 1\n case _: value = 1',
    'match token:\n case "up": value = 1\n case other: value = 1',
    'match token:\n case object(): value = "up"',
    'match token:\n case builtins.object(): value = "up"',
    'match token:\n case str(): value = "up"',
    'match raw:\n case "up": value = 1\n case object(): value = 1',
    'match raw:\n case object(): value = "up"',
    'match token:\n case "up" | _: value = 1',
])
def test_fallback_shapes_are_refused(source):
    assert any(fallback_node(node) for node in ast.walk(ast.parse(source)))


@pytest.mark.parametrize('source', [
    'value = tokens[token]',
    'stack.pop()',
    'stack.pop(0)',
    'match token:\n case "up": value = 1\n case "down": value = 0',
    'match token:\n case "up" | "ready": value = 1\n case "down": value = 0',
    'match fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)',
    'if valid:\n value = 1\nelse:\n value = 2',
])
def test_explicit_mapping_and_fact_dispatch_remain_valid(source):
    assert not any(fallback_node(node) for node in ast.walk(ast.parse(source)))


def test_import_resolved_factory_alias_is_refused():
    node = ast.parse('DD(lambda: "up")').body[0].value
    assert fallback_node(node, 'collections.defaultdict')
