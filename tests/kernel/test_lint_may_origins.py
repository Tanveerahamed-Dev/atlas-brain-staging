"""Nested alias reuse must not erase an outer prohibited API from any guard."""
import pytest

from atlas_brain.kernel.lints import lint


@pytest.mark.parametrize('origin,operation,rule', [
    ('typing.Optional', 'class Record:\n value: target[int]', 1),
    ('dataclasses.dataclass', '@target\nclass Record:\n value: int = 1', 2),
    ('atlas_brain.kernel.verdict.CheckResult', 'result = target()', 4),
    ('builtins.BaseException', 'try:\n pass\nexcept target:\n pass', 5),
    ('builtins.float', 'value = target("1")', 7),
    ('time.localtime', 'value = target()', 8),
    ('time.time', 'value = target()', 9),
    ('os.environ', 'value = target["STATE"]', 9),
    ('builtins.open', 'value = target("synthetic.txt")', 10),
    ('builtins.frozenset', 'for member in target(("a", "b")):\n pass', 11),
    ('re.compile', 'value = target("(a+)+")', 12),
    ('atlas_brain.kernel.states.Known', 'class Forged(target):\n pass', 13),
    ('importlib.import_module', 'value = target("pack")', 15),
])
@pytest.mark.parametrize('nested', ['def local():', 'class Local:'])
def test_nested_benign_import_cannot_hide_an_outer_guard_target(origin, operation, rule, nested):
    module, name = origin.rsplit('.', 1)
    outer = f'from {module} import {name} as target\n{operation}'
    assert rule in {number for number, _ in lint(outer, 'atlas_brain/packs/example/parser.py')}
    source = outer + f'\n{nested}\n from builtins import str as target\n reference = target'
    assert rule in {number for number, _ in lint(source, 'atlas_brain/packs/example/parser.py')}
