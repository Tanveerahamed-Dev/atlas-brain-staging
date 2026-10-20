import ast

import pytest

from atlas_brain.kernel.token_lints import bound_names, fallback_node


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
    'value = states[raw] if raw in states else "up"',
    'value = states[raw.state] if raw.state in states else "up"',
    'if raw in states:\n value = states[raw]\nelse:\n value = "up"',
    'value = fields["state"] if "state" in fields else "up"',
    'def mapped(raw):\n if raw == "up": return 1\n else: return 2',
    'value = 1 if raw == "up" else 2',
    'def mapped(raw):\n if raw == "up": return "up"\n else: return "up" + ""',
    'def mapped(raw):\n if raw == "up": raise ValueError("refused")\n else: return "up" + ""',
    'if raw == "up": value = "up"\nelse: value = "up" + ""',
    'value = "up" if raw == "up" else "up" + ""',
    'def assert_never(value): pass\ndef mapped(raw):\n match raw:\n  case _ as missing: assert_never(missing)\n return "up"',
    'match raw:\n case _ as missing: assert_never(missing)',
    'match raw:\n case _: value = "up"',
    'match raw:\n case other: value = "up"',
    'match raw:\n case str(): value = "up"',
    'match raw:\n case _ as missing:\n  assert_never(missing)\n  value = "up"',
    'match raw:\n case _ as missing: assert_never(other)',
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
    'value = states[raw]',
    'value = values[0] if valid else 0',
    'if valid:\n value = values[0]\nelse:\n value = 0',
    'index += 2 if pattern[index] == "\\\\" else 1',
    'match state:\n case "up": value = 1\n case "down": value = 0',
    'match fact:\n case Known(value=state): pass\n case _ as missing: assert_never(missing)',
    'match token:\n case "up": value = 1\n case "down": value = 0',
    'match token:\n case "up" | "ready": value = 1\n case "down": value = 0',
    'match fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)',
    'if valid:\n value = 1\nelse:\n value = 2',
])
def test_explicit_mapping_and_fact_dispatch_remain_valid(source):
    tree = ast.parse(source)
    # These structural fragments have a test-declared real assertion binding;
    # the public lint entry point separately proves actual source bindings.
    assertions = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Name) and node.func.id == 'assert_never')
    assert not any(fallback_node(node, assertions=assertions) for node in ast.walk(tree))


def test_import_resolved_factory_alias_is_refused():
    node = ast.parse('DD(lambda: "up")').body[0].value
    assert fallback_node(node, 'collections.defaultdict')


def test_pattern_binding_inventory_covers_all_capture_forms():
    tree = ast.parse('match value:\n case {"key": local, **rest}: pass\n case [*tail]: pass')
    assert bound_names(tree) == frozenset({'local', 'rest', 'tail'})
