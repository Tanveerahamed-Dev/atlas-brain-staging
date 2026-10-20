from pathlib import Path

import pytest

from atlas_brain.kernel.lints import lint


@pytest.mark.parametrize('rule,source', [
    (1, 'class Record:\n value: int | None'),
    (2, '@dataclass\nclass Record:\n value: int = 1'),
    (3, 'value = tokens.get(token, "up")'),
    (4, 'result = CheckResult()'),
    (5, 'try:\n pass\nexcept:\n pass'),
    (6, 'x = 1 # pyright: ignore[reportAssignmentType]'),
    (7, 'value = float("1")'),
    (8, 'import locale as loc\nloc.setlocale(1)'),
    (9, 'from os import getenv as env\nvalue = env("X")'),
    (10, 'text = open("synthetic.txt").read()'),
    (11, 'members = {"a", "b"}\nvalues = [x for x in members]'),
    (12, 'import re\npattern = re.compile("(a+)+", re.ASCII)'),
    (13, 'from atlas_brain.kernel.states import Known as K\nclass Forged(K):\n pass'),
    (14, 'from urllib.request import urlopen as load'),
    (15, 'import importlib as imp\nimp.import_module("pack")'),
])
def test_every_lint_fires_on_its_plant(rule, source):
    assert rule in {r for r, _ in lint(source, 'atlas_brain/packs/example/parser.py')}


@pytest.mark.parametrize('source,rule', [
    ('from typing import Optional as O\nclass R:\n value: O[int]', 1),
    ('@dataclasses.dataclass()\nclass R:\n value: int = field(default_factory=int)', 2),
    ('def map_token(token):\n if token == "up":\n  return 1\n else:\n  return 2', 3),
    ('from atlas_brain.kernel.verdict import CheckResult as R\nr = R()', 4),
    ('try:\n pass\nexcept BaseException as e:\n pass', 5),
    ('from math import sqrt', 7),
    ('x = 1 #pyright:ignore[reportAssignmentType]', 6),
    ('x = 1 # pyright: ignore[reportAssignmentType] reviewer:', 6),
    ('value = 1.5', 7),
    ('class R:\n value: float', 7),
    ('from zoneinfo import ZoneInfo as Z\nz = Z("UTC")', 8),
    ('import time\nx = time.localtime()', 8),
    ('import datetime as d\nx = d.datetime.now()', 9),
    ('from os import environ as env\nx = env["X"]', 9),
    ('from pathlib import Path\nx = Path("x").read_text()', 10),
    ('def f(xs: frozenset[str]):\n for x in xs:\n  pass', 11),
    ('import re as r\nx = r.compile("abc")', 12),
    ('class Forged(kernel.Unknown):\n pass', 13),
    ('class Forged(Known[int]):\n pass', 13),
    ('import socket as s', 14),
    ('from urllib import request as r', 14),
    ('x = __import__("pack")', 15),
])
def test_alias_and_alternate_plants(source, rule):
    assert rule in {r for r, _ in lint(source, 'atlas_brain/model/record.py')}


@pytest.mark.parametrize('source', [
    '@dataclass(frozen=True)\nclass Record:\n value: int',
    'value = tokens[token]',
    'x = 1 # pyright: ignore[reportAssignmentType] reviewer: REV',
    'with open("x", encoding="utf-8") as f:\n text = f.read()',
    'with open("x", "rb") as f:\n raw = f.read()',
    'values = {"a", "b"}\nresult = [x for x in sorted(values)]',
    'import re\nx = re.compile("[a-z]+", flags=re.ASCII)',
])
def test_valid_controls(source):
    assert lint(source, 'atlas_brain/packs/example/parser.py') == ()


def test_product_tree_passes_all_fifteen_lints():
    failures = [(p.as_posix(), lint(p.read_text(encoding='utf-8'), p.as_posix()))
                for p in sorted(Path('atlas_brain').rglob('*.py'))]
    assert not [(p, hits) for p, hits in failures if hits]


def test_result_constructor_exception_is_only_inside_verdict_function():
    path = 'atlas_brain/kernel/verdict.py'
    assert (4, 2) in lint('def helper():\n return CheckResult()', path)
    assert not lint('def verdict():\n def result():\n  return CheckResult()', path)


def test_runner_has_only_one_top_level_broad_handler():
    path = 'atlas_brain/runner/__main__.py'
    handler = 'try:\n pass\nexcept BaseException:\n pass\n'
    assert not lint(handler, path)
    assert 5 in {r for r, _ in lint(handler + handler, path)}
    assert 5 in {r for r, _ in lint('def unrelated():\n try:\n  pass\n except BaseException:\n  pass', path)}
