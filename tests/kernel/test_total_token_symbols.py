"""Name metadata has an explicit domain; a missing domain entry is an error."""
import ast
import inspect

import pytest

from atlas_brain.kernel import lints, token_lints



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



@pytest.mark.parametrize('name', ['symbol_environment', 'symbol_value', 'qualified_name'])
def test_symbol_domain_implementation_contains_no_implicit_default(name):
    function = getattr(token_lints, name, None)
    assert function is not None
    assert not tuple(item for item in lints.lint(inspect.getsource(function), 'atlas_brain/kernel/probe.py') if item[0] == 3)



def test_incomplete_constructed_domain_escapes_as_an_error(monkeypatch):
    monkeypatch.setattr(token_lints, 'symbol_environment', lambda tree, aliases: {})
    with pytest.raises(KeyError):
        token_lints._qualified(ast.Name(id='missing'), {})
