import ast

import pytest

from atlas_brain.kernel.token_lints import (
    binding_proof,
    bound_names,
    fallback_node,
    fallback_nodes,
)


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
    'def map_state(raw):\n if raw == "up": return "up"\n else: pass\n return "up"',
    'def map_state(raw):\n if raw == "up": return "up"\n if raw == "down": return "down"\n return "up"',
    'def map_state(raw):\n value = "up"\n if raw == "down": value = "down"\n return value',
    'class Known(str): pass\nmatch raw:\n case Known(): value = "up"',
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
    'def parse(pattern, index):\n if pattern[index] == "x": return index + 1\n return index',
    'if raw == "invalid": raise ValueError("refused")',
    'match state:\n case "up": value = 1\n case "down": value = 0',
    'match fact:\n case Known(value=state): pass\n case _ as missing: assert_never(missing)',
    'match token:\n case "up": value = 1\n case "down": value = 0',
    'match token:\n case "up" | "ready": value = 1\n case "down": value = 0',
    'match fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)',
    'if valid:\n value = 1\nelse:\n value = 2',
])
def test_explicit_mapping_and_fact_dispatch_remain_valid(source):
    tree = ast.parse(source)
    # These fragments declare a real assertion and an unhandled context;
    # the public entry point separately proves both from whole source.
    assertions = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Name) and node.func.id == 'assert_never')
    facts = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.MatchClass))
    assert not any(fallback_node(node, assertions=assertions, facts=facts, allow_refusal=True) for node in ast.walk(tree))


def test_import_resolved_factory_alias_is_refused():
    node = ast.parse('DD(lambda: "up")').body[0].value
    assert fallback_node(node, 'collections.defaultdict')


def test_pattern_binding_inventory_covers_all_capture_forms():
    tree = ast.parse('match value:\n case {"key": local, **rest}: pass\n case [*tail]: pass')
    assert bound_names(tree) == frozenset({'local', 'rest', 'tail'})


def test_canonical_binding_proof_rejects_import_and_capture_shadows():
    tree = ast.parse('match fact:\n case K(): pass\n case _ as missing: terminal(missing)')
    aliases = {'K': 'atlas_brain.kernel.states.Known', 'terminal': 'typing.assert_never'}
    calls, facts = binding_proof(tree, aliases, set())
    assert len(calls) == len(facts) == 1
    assert binding_proof(tree, aliases, {'typing'})[0] == frozenset()
    assert binding_proof(tree, aliases, {'atlas_brain.kernel.states'})[1] == frozenset()
    shadowed = ast.parse('match fact:\n case K(value=terminal): pass\n case _ as missing: terminal(missing)')
    assert binding_proof(shadowed, aliases, set())[0] == frozenset()


@pytest.mark.parametrize('ending', [
    'raise UnknownToken(raw)',
    'return atlas_brain.kernel.states.Unknown(reason=reason, detail="unmapped", evidence=(), candidates=(), next_evidence=())',
])
@pytest.mark.parametrize('branches', [
    ' if raw == "up": return "up"\n',
    ' if raw == "up": return "up"\n if raw == "down": return "down"\n',
])
def test_following_explicit_refusal_remains_valid(ending, branches):
    source = 'import atlas_brain.kernel.states\ndef map_state(raw):\n' + branches + ' ' + ending
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(raw):\n if raw == "up": pass\n return "up"',
    'def mapped(raw):\n if raw == "bad": raise UnknownToken(raw)\n return "up"',
    'def mapped(raw):\n if raw != "up": return "up"\n raise UnknownToken(raw)',
    'def mapped(raw, other):\n if raw == "up": return "up"\n if other == "down": return "up"\n raise UnknownToken(raw)',
    'def Unknown(*args): return "up"\ndef mapped(raw):\n if raw == "up": return "up"\n return Unknown(raw)',
    'def mapped(raw):\n if raw == "up": return "up"\n return "up"\n raise UnknownToken(raw)',
])
def test_following_healthy_or_unproven_default_is_refused(source):
    assert fallback_nodes(ast.parse(source), {}, set())


def test_following_unknown_witness_rejects_rebinding():
    tree = ast.parse('import atlas_brain.kernel.states\ndef mapped(raw):\n if raw == "up": return "up"\n return atlas_brain.kernel.states.Unknown()')
    assert fallback_nodes(tree, {}, {'atlas_brain.kernel.states.Unknown'})


@pytest.mark.parametrize('source', [
    'def map_state(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except ValueError:\n  return "up"',
    'def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n finally:\n  return "up"',
    'import atlas_brain.kernel.states\ndef mapped(raw):\n try:\n  if raw == "up": return "up"\n  return atlas_brain.kernel.states.Unknown()\n finally:\n  return "up"',
    'def mapped(raw):\n with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n try:\n  try:\n   if raw == "up": return "up"\n   raise ValueError("unmapped")\n  finally: pass\n except ValueError: return "up"',
])
def test_enclosing_control_flow_cannot_turn_refusal_into_health(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(raw):\n try: pass\n except ValueError: pass\n else:\n  if raw == "up": return "up"\n  raise UnknownToken(raw)',
    'def mapped(raw):\n with manager:\n  def local(raw):\n   if raw == "up": return "up"\n   raise UnknownToken(raw)\n return local(raw)',
])
def test_uncaught_refusal_in_else_and_separate_function_remains_valid(source):
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'import typing\ndef mapped(raw):\n try:\n  match raw:\n   case "up": return "up"\n   case _ as missing: typing.assert_never(missing)\n except AssertionError: return "up"',
    'def mapped(raw):\n match raw:\n  case "up": return "up"\n  case "down": return "down"\n return "up"',
    'def mapped(raw):\n try:\n  match raw:\n   case "up": return "up"\n  raise ValueError("unmapped")\n except ValueError: return "up"',
])
def test_match_refusals_must_escape_and_literal_arms_cannot_hide_fallthrough(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('ending', ['raise UnknownToken(raw)', 'return atlas_brain.kernel.states.Unknown()'])
def test_literal_match_with_explicit_uncaught_unknown_remains_valid(ending):
    source = 'import atlas_brain.kernel.states\ndef mapped(raw):\n match raw:\n  case "up": return "up"\n ' + ending
    assert not fallback_nodes(ast.parse(source), {}, set())
