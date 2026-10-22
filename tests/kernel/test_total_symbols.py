"""Name metadata has an explicit domain; a missing domain entry is an error."""
import ast
import inspect

import pytest

from atlas_brain.kernel import lints, token_lints


@pytest.mark.parametrize('resolver', [lints.resolved_name, lints.possible_names, token_lints._qualified])
def test_resolver_source_has_no_missing_key_default(resolver):
    source = inspect.getsource(resolver)
    assert not tuple(item for item in lints.lint(source, 'atlas_brain/kernel/probe.py') if item[0] == 3)


def test_total_symbol_domain_covers_names_and_all_binding_forms():
    tree = ast.parse('import re as rx\nclass Record: pass\nasync def worker(arg): pass\n'
                     'try: pass\nexcept ValueError as failure: pass\n'
                     'match value:\n case {"key": capture, **rest}: pass\n case [*tail]: pass')
    construct = getattr(token_lints, 'symbol_environment', None)
    assert construct is not None
    aliases = {'rx': 're'}
    environment = construct(tree, aliases)
    expected = {'Record', 'worker', 'arg', 'ValueError', 'failure', 'value', 'capture', 'rest', 'tail'}
    assert expected <= environment.keys()
    assert all(environment[name] == name for name in expected)
    assert environment['rx'] == 're'
    assert aliases == {'rx': 're'}


def test_symbol_subscription_refuses_missing_key_without_a_default():
    lookup = getattr(token_lints, 'symbol_value', None)
    assert lookup is not None
    assert lookup('entry', {'entry': 'module.entry'}) == 'module.entry'
    with pytest.raises(KeyError):
        lookup('missing', {'entry': 'module.entry'})


@pytest.mark.parametrize('expression,aliases,expected', [
    ('item', {}, 'item'),
    ('rx.ASCII', {'rx': 're'}, 're.ASCII'),
    ('table[key]', {'table': 'module.values'}, 'module.values'),
])
def test_total_resolution_keeps_existing_name_and_import_semantics(expression, aliases, expected):
    node = ast.parse(expression, mode='eval').body
    assert lints.resolved_name(node, aliases) == expected
    assert aliases == dict(aliases)
