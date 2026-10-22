"""Boolean syntax predicates and violation collection are not token-map defaults."""
import inspect

import pytest

from atlas_brain.kernel.lints import lint, nested_unbounded, node_rules


@pytest.mark.parametrize('function', [nested_unbounded, node_rules])
def test_boolean_metadata_source_has_no_token_default(function):
    assert not tuple(item for item in lint(inspect.getsource(function), 'atlas_brain/kernel/probe.py') if item[0] == 3)


@pytest.mark.parametrize('source,refused', [
    ('open("data", "rb")', False),
    ('handle.open("rb")', False),
    ('open("data", mode="rb")', False),
    ('open("data", "rb", mode="r")', True),
    ('open("data", "r", encoding="utf-8")', False),
    ('open("data")', True),
    ('handle.read_text(encoding="utf-8")', False),
    ('handle.read_text(encoding=None)', True),
    ('handle.read_text()', True),
    ('open()', True),
])
def test_absent_mode_and_encoding_remain_refusals(source, refused):
    assert any(rule == 10 for rule, _ in lint(source, 'atlas_brain/kernel/probe.py')) is refused


@pytest.mark.parametrize('source,refused', [
    ('re.compile("literal", re.ASCII)', False),
    ('re.search("literal", "text", re.ASCII)', False),
    ('re.compile("literal")', True),
    ('re.search("literal", "text")', True),
    ('re.compile(pattern, re.ASCII)', True),
    ('re.compile()', True),
])
def test_absent_or_dynamic_regex_arguments_remain_refusals(source, refused):
    assert any(rule == 12 for rule, _ in lint(source, 'atlas_brain/kernel/probe.py')) is refused


@pytest.mark.parametrize('pattern,refused', [
    ('(a+)+', True), ('(a{1,})*', True), ('((a+))*', True),
    ('[()+*]+', False), (r'\(a\+\)+', False), ('(ab)+', False),
    ('(a+)(b+)', False), ('(a?)+', False),
])
def test_regex_boolean_state_keeps_escapes_classes_and_group_boundaries(pattern, refused):
    assert nested_unbounded(pattern) is refused


@pytest.mark.parametrize('source,path,refused', [
    ('import os\nvalue = os.environ', 'atlas_brain/kernel/probe.py', True),
    ('from os import environ as env\nvalue = env', 'atlas_brain/kernel/probe.py', True),
    ('import os\nvalue = os.environb', 'atlas_brain/kernel/probe.py', True),
    ('import os\nvalue = os.environ', 'atlas_brain/runner/worker.py', False),
    ('value = local.environ', 'atlas_brain/kernel/probe.py', False),
])
def test_environment_access_still_emits_the_same_rule_nine_witness(source, path, refused):
    assert any(rule == 9 for rule, _ in lint(source, path)) is refused
