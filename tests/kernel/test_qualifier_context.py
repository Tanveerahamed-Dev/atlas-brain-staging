"""Paired source-context contract; these witnesses do not waive any lint."""
import ast
from pathlib import Path

import pytest

from atlas_brain.kernel import lints


def source_context():
    paths = tuple(sorted(p.as_posix() for p in Path('atlas_brain').rglob('*.py')))
    sources = {path: Path(path).read_text(encoding='utf-8') for path in paths}
    return sources, paths


def selected_lines(source, name):
    function = next(n for n in ast.parse(source).body
                    if isinstance(n, ast.FunctionDef) and n.name == name)
    branch = next(n for n in function.body if isinstance(n, ast.If))
    guard = next(n for n in branch.body if isinstance(n, ast.If))
    lookup = next(n for n in ast.walk(branch)
                  if isinstance(n, ast.Return) and isinstance(n.value, ast.Subscript))
    return branch.lineno, guard.lineno, lookup.lineno


@pytest.mark.parametrize('path,name', [
    ('atlas_brain/kernel/lints.py', 'resolved_name'),
    ('atlas_brain/kernel/token_lints.py', '_qualified'),
])
def test_current_qualifier_pair_has_a_finite_metadata_witness(path, name):
    sources, inventory = source_context()
    source = sources[path]
    lines = selected_lines(source, name)
    # Record the existing scanner's three observations before any proof is used.
    assert {(3, line) for line in lines} <= set(lints.lint(source, path))
    refusals = []
    assert lints.qualifier_witnesses(source, path, sources, inventory, refusals=refusals) == lines, refusals


@pytest.mark.parametrize('path,name', [
    ('atlas_brain/kernel/lints.py', 'resolved_name'),
    ('atlas_brain/kernel/token_lints.py', '_qualified'),
])
@pytest.mark.parametrize('consumer', [
    ('from MODULE import HELPER\nfrom atlas_brain.kernel.states import Known\n'
    'def consume(node, aliases, basis, evidence, raw):\n'
    ' return Known(value=HELPER(node, aliases), basis=basis, evidence=evidence, raw=raw)\n'),
    'from MODULE import HELPER as forwarded\n',
    'import MODULE as helpers\ndef consume(node, aliases):\n return helpers.HELPER(node, aliases)\n',
    'from MODULE import *\n',
    'import atlas_brain\ndef consume():\n return atlas_brain.kernel\n',
    'import importlib as loader\nhelper = loader.import_module("MODULE")\n',
    ('import ast\nfrom MODULE import HELPER\ndef qualifier_witnesses(node, aliases):\n'
     ' return {"healthy": HELPER(node, aliases)}\n'),
])
def test_identical_qualifier_is_refused_with_new_or_unresolved_product_consumer(path, name, consumer):
    sources, inventory = source_context()
    source = sources[path]
    module = path[:-3].replace('/', '.')
    extra = 'atlas_brain/model/metadata_sink_probe.py'
    sources[extra] = consumer.replace('MODULE', module).replace('HELPER', name)
    inventory = tuple(sorted((*inventory, extra)))
    assert sources[path] == source
    assert lints.qualifier_witnesses(source, path, sources, inventory) == ()


@pytest.mark.parametrize('damage', ['missing', 'extra', 'mismatched', 'duplicate'])
def test_context_requires_exact_current_file_and_complete_independent_inventory(damage):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    source = sources[path]
    if damage == 'missing':
        del sources['atlas_brain/evidence/capture.py']
    elif damage == 'extra':
        sources['atlas_brain/model/opaque.py'] = 'def consume(): return 1\n'
    elif damage == 'mismatched':
        sources[path] += '\ndef consume(): return 1\n'
    else:
        inventory += (path,)
    assert lints.qualifier_witnesses(source, path, sources, inventory) == ()


@pytest.mark.parametrize('before,after', [
    ('return node.id', 'return "typing.assert_never"'),
    ("return ''", 'return "re.ASCII"'),
    ('return aliases[node.id]', 'return aliases["healthy"]'),
    ('dict(bindings)', '{"assert_never": "typing.assert_never"}'),
    ('bindings = import_bindings(tree)', 'bindings = (("safe", "typing.assert_never"),)'),
    ('for node in ast.walk(tree):', 'for node in ():'),
    ('import ast', 'import fake_ast as ast'),
])
def test_fabricated_qualifier_or_origin_producer_cannot_obtain_a_witness(before, after):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    changed = sources[path].replace(before, after)
    assert changed != sources[path]
    sources[path] = changed
    assert lints.qualifier_witnesses(changed, path, sources, inventory) == ()


def test_unknown_consumer_inside_scanner_is_not_lint_metadata():
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    sources[path] += '\ndef consume(node, aliases):\n return {"healthy": resolved_name(node, aliases)}\n'
    assert lints.qualifier_witnesses(sources[path], path, sources, inventory) == ()


@pytest.mark.parametrize('change', [
    '\ndef isinstance(node, kind):\n return True\n',
    '\ndef dict(bindings):\n return {"safe": "typing.assert_never"}\n',
    '\ndef consume(node, aliases):\n return resolved_name(node, aliases)\nconsume_alias = consume\n',
])
def test_shadowed_builtins_and_escaped_functions_are_unproved(change):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    sources[path] += change
    assert lints.qualifier_witnesses(sources[path], path, sources, inventory) == ()


@pytest.mark.parametrize('before,after', [
    ('resolved_name(n, aliases)', 'resolved_name(n, {"safe": "typing.assert_never"})'),
    ('fallback_nodes(tree, aliases, rebound)', 'fallback_nodes(tree, {"safe": "typing.assert_never"}, rebound)'),
    ('tree = ast.parse(source)', 'tree = ast.parse("import typing")'),
    ('findings.add((6, lineno))', 'findings.add(("healthy", lineno))'),
])
def test_forged_argument_ast_producer_and_nonfinding_result_are_unproved(before, after):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    changed = sources[path].replace(before, after)
    assert changed != sources[path]
    sources[path] = changed
    assert lints.qualifier_witnesses(changed, path, sources, inventory) == ()


def test_nested_same_named_consumer_is_not_merged_with_a_reachable_scope():
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/token_lints.py'
    original = 'def bound_names(node: ast.AST) -> frozenset[str]:\n'
    changed = sources[path].replace(original, original + (
        '    def stable(value):\n        return {"healthy": _qualified(value, {})}\n'))
    assert changed != sources[path]
    sources[path] = changed
    assert lints.qualifier_witnesses(changed, path, sources, inventory) == ()


@pytest.mark.parametrize('body', [
    'class Refused(ValueError):\n def __init__(self, reason):\n  super().__init__(reason)\n',
    'class Refused(ValueError):\n def __init__(self, reason):\n  super().__init__(reason)\n\n# ordinary constructor\n',
])
def test_unrelated_ordinary_base_initializer_does_not_expose_metadata(body):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    extra = 'atlas_brain/model/initializer_probe.py'
    sources[extra] = body
    inventory = tuple(sorted((*inventory, extra)))
    assert lints.qualifier_witnesses(sources[path], path, sources, inventory) == selected_lines(sources[path], 'resolved_name')


@pytest.mark.parametrize('body', [
    'def consume(value):\n return value.__class__\n',
    'def consume(value):\n value.__init__()\n',
    'class Refused(ValueError):\n def expose(self):\n  return super().__init__\n',
    'def consume(super):\n super().__init__()\n',
    'from other import constructor as super\nsuper().__init__()\n',
    'def super():\n return value\nsuper().__init__()\n',
    'super = value\nsuper().__init__()\n',
    'def consume(value):\n match value:\n  case {"constructor": super}:\n   super().__init__()\n',
])
def test_reflection_or_shadowed_constructor_is_still_unproved(body):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    extra = 'atlas_brain/model/initializer_probe.py'
    sources[extra] = body
    inventory = tuple(sorted((*inventory, extra)))
    assert lints.qualifier_witnesses(sources[path], path, sources, inventory) == ()


@pytest.mark.parametrize('before,after', [
    ('    aliases, rebound = binding_environment(tree)\n',
     ('    aliases, rebound = binding_environment(tree)\n'
      '    bindings = (("forged", "typing.assert_never"),)\n    aliases = dict(bindings)\n')),
    ('    aliases, rebound = binding_environment(tree)\n',
     '    aliases, rebound = binding_environment(ast.parse("from typing import assert_never as forged"))\n'),
    ('    tree = ast.parse(source)\n',
     '    tree = ast.parse(source)\n    tree = ast.parse("from typing import assert_never as forged")\n'),
])
def test_root_cannot_forge_the_ast_or_import_environment(before, after):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    changed = sources[path].replace(before, after)
    assert changed != sources[path]
    assert selected_lines(changed, 'resolved_name') != ()
    sources[path] = changed
    assert lints.qualifier_witnesses(changed, path, sources, inventory) == ()


@pytest.mark.parametrize('before,after', [
    ('    aliases, rebound = binding_environment(tree)\n',
     ('    aliases, rebound = binding_environment(tree)\n'
      '    forwarded = aliases\n    forwarded["forged"] = "typing.assert_never"\n')),
    ('    tree = ast.parse(source)\n',
     ('    tree = ast.parse(source)\n    forwarded = tree.body\n'
      '    forwarded[:] = ast.parse("from typing import assert_never as forged").body\n')),
    ('    return any(resolved_tail(part, aliases) in names for part in ast.walk(node))\n',
     ('    forwarded = aliases\n    forwarded["forged"] = "typing.assert_never"\n'
      '    return any(resolved_tail(part, aliases) in names for part in ast.walk(node))\n')),
    ('    origins = {name: (origin,) for name, origin in aliases.items()} | import_origins(tree)\n',
     ('    forwarded = tree.body\n'
      '    forwarded[:] = ast.parse("from typing import assert_never as forged").body\n'
      '    origins = {name: (origin,) for name, origin in aliases.items()} | import_origins(tree)\n')),
])
def test_root_or_reachable_helper_cannot_mutate_producers_through_an_alias(before, after):
    sources, inventory = source_context()
    path = 'atlas_brain/kernel/lints.py'
    changed = sources[path].replace(before, after)
    assert changed != sources[path]
    sources[path] = changed
    assert lints.qualifier_witnesses(changed, path, sources, inventory) == ()
