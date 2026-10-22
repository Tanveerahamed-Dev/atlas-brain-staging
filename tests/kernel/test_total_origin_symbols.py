"""Name metadata has an explicit domain; a missing domain entry is an error."""
import ast
import inspect

import pytest

from atlas_brain.kernel import lints, token_lints



@pytest.mark.parametrize('resolver', [lints.resolved_name, lints.possible_names, token_lints._qualified])
def test_resolver_source_has_no_missing_key_default(resolver):
    source = inspect.getsource(resolver)
    assert not tuple(item for item in lints.lint(source, 'atlas_brain/kernel/probe.py') if item[0] == 3)



@pytest.mark.parametrize('expression,aliases,expected', [
    ('item', {}, 'item'),
    ('rx.ASCII', {'rx': 're'}, 're.ASCII'),
    ('table[key]', {'table': 'module.values'}, 'module.values'),
])
def test_total_resolution_keeps_existing_name_and_import_semantics(expression, aliases, expected):
    node = ast.parse(expression, mode='eval').body
    before = dict(aliases)
    assert lints.resolved_name(node, aliases) == expected
    assert aliases == before



def test_origin_subscription_refuses_missing_key_without_an_identity_origin():
    lookup = getattr(lints, 'origin_value', None)
    assert lookup is not None
    assert lookup('entry', {'entry': ('module.entry', 'other.entry')}) == ('module.entry', 'other.entry')
    with pytest.raises(KeyError):
        lookup('missing', {'entry': ('module.entry',)})



def test_total_origins_preserve_every_conflicting_import():
    tree = ast.parse('from dataclasses import dataclass\nfrom typing import ClassVar as C\n'
                     'from other import C\n@dataclass\nclass Record:\n x: C[int] = 1')
    origins = lints.import_origins(tree)
    annotation = next(node.annotation for node in ast.walk(tree) if isinstance(node, ast.AnnAssign))
    assert lints.possible_names(annotation, origins) == ('other.C', 'typing.ClassVar')
    assert any(rule == 2 for rule, _ in lints.lint(ast.unparse(tree), 'atlas_brain/model/probe.py'))



@pytest.mark.parametrize('prefix,refused', [
    ('', True),
    ('from atlas_brain.kernel.states import Unknown\n', False),
    ('from builtins import str as Unknown\nfrom atlas_brain.kernel.states import Unknown\n', True),
])
def test_public_token_refusal_requires_an_actual_unambiguous_import(prefix, refused):
    source = prefix + 'def mapped(raw, values):\n if raw in values:\n  return values[raw]\n return Unknown("missing")'
    assert any(rule == 3 for rule, _ in lints.lint(source, 'atlas_brain/kernel/probe.py')) is refused



def test_public_scanner_does_not_turn_a_broken_symbol_domain_into_success(monkeypatch):
    monkeypatch.setattr(token_lints, 'symbol_environment', lambda tree, aliases: {})
    with pytest.raises(KeyError):
        lints.lint('factory(value)', 'atlas_brain/kernel/probe.py')
