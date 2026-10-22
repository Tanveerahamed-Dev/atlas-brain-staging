"""Nested alias reuse must not erase an outer prohibited API from any guard."""
import ast

import pytest

from atlas_brain.kernel.lints import (
    FACT_PATH,
    binding_environment,
    import_origins,
    node_rules,
    resolved_name,
    unordered_iterations,
)
from atlas_brain.kernel.token_lints import bound_names


def scan_nodes(source: str, path: str) -> tuple[tuple[int, int], ...]:
    tree = ast.parse(source)
    aliases, rebound = binding_environment(tree)
    origins = import_origins(tree)
    shadowed = rebound | {resolved_name(ast.Name(id=name, ctx=ast.Load()), aliases) for name in bound_names(tree)}
    parts = path.split('/')
    findings = {finding for node in ast.walk(tree) for finding in node_rules(
        node, path, aliases, origins, rebound, shadowed, fact_path=any(part in FACT_PATH for part in parts),
        fact_fields='model' in parts or 'packs' in parts, in_verdict=False,
        in_pk_compiler=False, pk_compiler_source=False)}
    findings.update((11, node.lineno if isinstance(node, (ast.stmt, ast.expr, ast.ExceptHandler)) else 1)
                    for node in unordered_iterations(tree, aliases))
    return tuple(sorted(findings))


@pytest.mark.parametrize('origin,operation,rule', [
    ('typing.Optional', 'class Record:\n value: target[int]', 1),
    ('dataclasses.dataclass', '@target\nclass Record:\n value: int = 1', 2),
    ('collections.defaultdict', 'values = target(lambda: "up")', 3),
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
    assert rule in {number for number, _ in scan_nodes(outer, 'atlas_brain/packs/example/parser.py')}
    source = outer + f'\n{nested}\n from builtins import str as target\n reference = target'
    assert rule in {number for number, _ in scan_nodes(source, 'atlas_brain/packs/example/parser.py')}


@pytest.mark.parametrize('nested', ['def local():', 'class Local:'])
def test_conflicting_classvar_origin_does_not_exempt_a_real_dataclass_field(nested):
    source = ('from dataclasses import dataclass\nfrom builtins import int as CV\n'
              '@dataclass\nclass Record:\n value: CV = 1\n'
              f'{nested}\n from typing import ClassVar as CV\n reference = CV')
    assert 2 in {number for number, _ in scan_nodes(source, 'atlas_brain/model/record.py')}


@pytest.mark.parametrize('tail', ['', '\ndef local():\n from typing import ClassVar as CV\n reference = CV'])
def test_genuine_classvar_imports_preserve_the_field_exemption(tail):
    source = ('from dataclasses import dataclass\nfrom typing import ClassVar as CV\n'
              '@dataclass\nclass Record:\n value: CV[int] = 1' + tail)
    assert 2 not in {number for number, _ in scan_nodes(source, 'atlas_brain/model/record.py')}
