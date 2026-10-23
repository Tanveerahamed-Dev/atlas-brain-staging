"""A nested import cannot erase the existing unordered-builtin refusal."""
import ast

import pytest

from atlas_brain.kernel.lints import binding_environment, unordered_iterations


def iteration_findings(source):
    tree = ast.parse(source)
    return unordered_iterations(tree, binding_environment(tree)[0])


@pytest.mark.parametrize('factory', ['set', 'frozenset'])
@pytest.mark.parametrize('nested', ['def local():', 'class Local:'])
def test_nested_import_cannot_hide_a_real_unordered_builtin(factory, nested):
    operation = f'items = {factory}(("a", "b"))\nfor item in items: pass'
    assert iteration_findings(operation)
    source = operation + f'\n{nested}\n from builtins import str as {factory}\n reference = {factory}'
    assert iteration_findings(source)


@pytest.mark.parametrize('factory', ['set', 'frozenset'])
def test_module_shadow_import_is_not_an_unordered_builtin(factory):
    source = f'from builtins import str as {factory}\nitems = {factory}(("a", "b"))\nfor item in items: pass'
    assert not iteration_findings(source)


@pytest.mark.parametrize('factory', ['set', 'frozenset'])
@pytest.mark.parametrize('scope', ['def local():', 'class Local:'])
def test_local_shadow_import_is_not_an_unordered_builtin(factory, scope):
    source = f'{scope}\n from builtins import str as {factory}\n items = {factory}(("a", "b"))\n for item in items: pass'
    assert not iteration_findings(source)


@pytest.mark.parametrize('source', [
    'items = set(("a",))\nfrom builtins import str as set\nfor item in items: pass',
    'from builtins import str as set\ndel set\nitems = set(("a",))\nfor item in items: pass',
    'class Outer:\n from builtins import str as set\n def inspect(self):\n  for item in set(("a",)): pass',
])
def test_builtin_reachability_cannot_be_replaced_by_a_later_import(source):
    assert iteration_findings(source)


def test_first_comprehension_iterable_keeps_its_real_class_scope():
    source = 'class Outer:\n from builtins import str as set\n items = [item for item in set(("a",))]'
    assert not iteration_findings(source)


def test_unordered_runtime_value_and_guard_are_paired():
    source = ('items = frozenset(("a", "b"))\nfor item in items: pass\n'
              'def local():\n from builtins import str as frozenset\n reference = frozenset')
    namespace = {}
    exec(source, namespace)
    assert type(namespace['items']) is frozenset
    assert iteration_findings(source)
