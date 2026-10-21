from pathlib import Path

import pytest

from atlas_brain.kernel.lints import lint


@pytest.mark.parametrize('path,rule,source', [
    ('atlas_brain/packs/example/parser.py', rule, source) for rule, source in [
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
    ]
] + [('atlas_brain/model/record.py', rule, source) for source, rule in [
    ('from typing import Optional as O\nclass R:\n value: O[int]', 1),
    ('@dataclasses.dataclass()\nclass R:\n value: int = field(default_factory=int)', 2),
    ('def map_token(token):\n if token == "up":\n  return 1\n else:\n  return 2', 3),
    ('value = tokens.setdefault(token, "up")', 3),
    ('value = tokens.pop(token, "up")', 3),
    ('value = states[raw] if raw in states else "up"', 3),
    ('states = {"up": "up"}\ndef map_state(raw: str) -> str:\n if raw in states: return states[raw]\n return "up"', 3),
    ('states = {"up": "up"}\ndef map_state(raw):\n for _ in ():\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('def mapped(key):\n for item in ():\n  return mapping[key]\n return "up"', 3),
    ('def mapped(raw):\n try: pass\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('def mapped(raw, ready):\n try: raise ValueError("entered")\n except ValueError:\n  if ready: return "up"\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")', 3),
    ('def mapped(raw, ready):\n if ready: return "up"\n if raw == "up": return "up"\n raise ValueError("unmapped")', 3),
    ('import atlas_brain.kernel.states\ndef mapped(raw, ready):\n if ready: return "up"\n if raw not in states: return atlas_brain.kernel.states.Unknown()\n return states[raw]', 3),
    ('def mapped(raw):\n try: raise KeyError("entered")\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n except KeyError: return "up"', 3),
    ('def mapped(raw):\n try: raise ValueError("entered")\n except ValueError: pass\n else:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('def mapped(raw):\n value = "up"\n for _ in ():\n  value = states[raw]\n return value', 3),
    ('def mapped(raw):\n value: str = "up"\n for _ in ():\n  value: str = states[raw]\n return value', 3),
    ('def mapped(raw):\n value = 0\n for _ in ():\n  value += states[raw]\n return value', 3),
    ('def mapped(raw):\n value = "up"\n for _ in ():\n  (value := states[raw])\n return value', 3),
    ('def mapped(raw):\n value = "up"\n for _ in ():\n  def ignored(value=states[raw]): pass\n return value', 3),
    ('def mapped(raw):\n value = "up"\n for _ in ():\n  @states[raw]\n  def ignored(): pass\n return value', 3),
    ('def mapped(raw):\n return "up"\n if raw in states: return states[raw]\n raise ValueError("unmapped")', 3),
    ('def factory(label):\n if label == "ready":\n  def mapped(key):\n   for item in ():\n    return mapping[key]\n   return "up"\n  return mapped\n raise ValueError("unmapped")', 3),
    ('def mapped(key):\n while ready:\n  return mapping[key]\n return "up"', 3),
    ('def mapped(key):\n while ready:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('async def mapped(key):\n async for item in rows:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('def mapped(key):\n for item in rows: break\n else:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"', 3),
    ('states = {"up": "up"}\ndefaults = {"healthy": "up"}\ndef map_state(raw: str) -> str:\n if raw not in states: return defaults["healthy"]\n raise ValueError("unmapped")', 3),
    ('def mapped(key):\n if key not in mapping: return "up"\n return mapping[key]', 3),
    ('def mapped(key):\n if key in mapping: return other[key]\n raise ValueError("unmapped")', 3),
    ('def mapped(key, other):\n if key in mapping: return mapping[other]\n raise ValueError("unmapped")', 3),
    ('def mapped(packet):\n value = "up"\n if packet.code in registry: value = registry[packet.code]\n return value', 3),
    ('def mapped(entry):\n try:\n  if entry in table: return table[entry]\n  raise ValueError("unmapped")\n except ValueError: return "up"', 3),
    ('match raw:\n case _: value = "up"', 3),
    ('def mapped(raw):\n if raw == "up": return "up"\n else: return "up" + ""', 3),
    ('def map_state(raw):\n if raw == "up": return "up"\n else: pass\n return "up"', 3),
    ('def map_state(raw):\n if raw == "up": return "up"\n if raw == "down": return "down"\n return "up"', 3),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except ValueError: return "up"', 3),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n finally: return "up"', 3),
    ('def mapped(raw):\n with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n return "up"', 3),
    ('import typing\ndef mapped(raw):\n try:\n  match raw:\n   case "up": return "up"\n   case _ as missing: typing.assert_never(missing)\n except AssertionError: return "up"', 3),
    ('def mapped(raw):\n match raw:\n  case "up": return "up"\n  case "down": return "down"\n return "up"', 3),
    ('import atlas_brain.kernel.states\ndef mapped(fact):\n match fact:\n  case atlas_brain.kernel.states.Known(): return "up"\n return "up"', 3),
    ('import typing\ndef mapped(raw):\n match raw:\n  case _ as missing if False: typing.assert_never(missing)\n return "up"', 3),
    ('import typing\ndef mapped(raw):\n match raw:\n  case "up" as missing: typing.assert_never(missing)\n return "up"', 3),
    ('class Known(str): pass\nmatch raw:\n case Known(): value = "up"', 3),
    ('def Unknown(*args): return "up"\ndef mapped(raw):\n if raw == "up": return "up"\n return Unknown(raw)', 3),
    ('def mapped(raw):\n if raw != "up": return "up"\n raise UnknownToken(raw)', 3),
    ('def assert_never(value): pass\ndef mapped(raw):\n match raw:\n  case _ as missing: assert_never(missing)\n return "up"', 3),
    ('from typing import assert_never\ndef assert_never(value): pass\ndef mapped(raw):\n match raw:\n  case _ as missing: assert_never(missing)\n return "up"', 3),
    ('from typing import assert_never\ndef mapped(fact, raw):\n match fact:\n  case Known(value=assert_never): pass\n match raw:\n  case _ as missing: assert_never(missing)\n return "up"', 3),
    ('match fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)', 3),
    ('from collections import defaultdict as DD\nvalues = DD(lambda: "up")', 3),
    ('value = tokens.get(token) or "up"', 3),
    ('def map_token(token):\n match token:\n  case object(): return "up"', 3),
    ('def map_token(token):\n match token:\n  case "up": return 1\n  case _: return 1', 3),
    ('def map_token(token):\n match token:\n  case "up": return 1\n  case other: return 1', 3),
    ('from atlas_brain.kernel.verdict import CheckResult as R\nr = R()', 4),
    ('try:\n pass\nexcept BaseException as e:\n pass', 5),
    ('from math import sqrt', 7),
    ('x = 1 #pyright:ignore[reportAssignmentType]', 6),
    ('x = 1 # pyright: ignore[reportAssignmentType] reviewer:', 6),
    ('value = 1.5', 7),
    ('value = 1j', 7),
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
]])
def test_every_lint_and_alternate_plant(path, rule, source):
    assert rule in {r for r, _ in lint(source, path)}


@pytest.mark.parametrize('path,source', [
    ('atlas_brain/packs/example/parser.py', source) for source in [
    '@dataclass(frozen=True)\nclass Record:\n value: int',
    'value = tokens[token]',
    'def mapped(key):\n if key in mapping: return mapping[key]\n raise ValueError("unmapped")',
    'def mapped(key):\n if key == "up": return mapping[key]\n raise ValueError("unmapped")',
    'def mapped(raw):\n try: raise ValueError("entered")\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n value = states[raw]\n return value',
    'def mapped(raw):\n if raw == "up":\n  value = states[raw]\n  return value\n raise ValueError("unmapped")',
    'def factory(label):\n if label == "ready":\n  def mapped(key):\n   if key in mapping: return mapping[key]\n   raise ValueError("unmapped")\n  return mapped\n raise ValueError("unmapped")',
    'from atlas_brain.kernel.states import Unknown as U\ndef mapped(key):\n if key not in mapping: return U()\n return mapping[key]',
    'def mapped(fields):\n if "state" in fields: return fields["state"]\n raise ValueError("unmapped")',
    'def mapped(raw):\n if raw == "up": return "up"\n raise UnknownToken(raw)',
    'from atlas_brain.kernel.states import Unknown as U\ndef mapped(raw):\n if raw == "up": return "up"\n return U(reason=reason, detail="unmapped", evidence=(), candidates=(), next_evidence=())',
    'values = (1, True, None, Ellipsis, "token", b"bytes")',
    'match token:\n case "up": value = 1\n case "down": value = 0',
    'from atlas_brain.kernel.states import Known\nfrom typing import assert_never\nmatch fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)',
    'from atlas_brain.kernel.states import Known\nfrom typing import assert_never as terminal\nmatch fact:\n case Known(): pass\n case _ as impossible: terminal(impossible)',
    'from atlas_brain.kernel.states import Known\nimport typing as t\nmatch fact:\n case Known(): pass\n case _ as impossible: t.assert_never(impossible)',
    'x = 1 # pyright: ignore[reportAssignmentType] reviewer: REV',
    'with open("x", encoding="utf-8") as f:\n text = f.read()',
    'with open("x", "rb") as f:\n raw = f.read()',
    'values = {"a", "b"}\nresult = [x for x in sorted(values)]',
    'import re\nx = re.compile("[a-z]+", flags=re.ASCII)',
    'import re\nfrom re import ASCII as F\nx = re.compile("abc", F)',
    ]
] + [('atlas_brain/evidence/admission.py', source) for source in [
    'from pathlib import Path\nwith Path("x").open("rb") as f:\n raw = f.read()',
    'with path.open("rb") as f:\n raw = f.read()',
    'with path.open(mode="rb") as f:\n raw = f.read()',
    'from pathlib import Path\nwith Path.open(path, "rb") as f:\n raw = f.read()',
    'import io\nwith io.open("x", "rb") as f:\n raw = f.read()',
]])
def test_valid_controls(path, source):
    assert lint(source, path) == ()


def test_product_tree_passes_all_fifteen_lints():
    failures = [(p.as_posix(), lint(p.read_text(encoding='utf-8'), p.as_posix()))
                for p in sorted(Path('atlas_brain').rglob('*.py'))]
    active = [(p, hits) for p, hits in failures if hits]
    assert not active, repr(active)


def test_constructor_boundary_and_finding_locations():
    assert (4, 2) in lint('def helper():\n return CheckResult()', 'atlas_brain/kernel/verdict.py')
    assert not lint('def verdict():\n def result():\n  return CheckResult()', 'atlas_brain/kernel/verdict.py')
    assert lint('x = 1\nvalue = tokens.get(token, "up")', 'atlas_brain/packs/example/parser.py') == ((3, 2),)


@pytest.mark.parametrize('path', ['atlas_brain/runner/__main__.py', 'atlas_brain/runner/worker.py'])
@pytest.mark.parametrize('source', [
    'try:\n pass\nexcept BaseException:\n pass\n',
    'try:\n pass\nexcept BaseException:\n raise SystemExit(1)\n',
    'try:\n pass\nexcept BaseException:\n raise SystemExit(1)\n' * 2,
    'def unrelated():\n try:\n  pass\n except BaseException:\n  pass',
    'def SystemExit(code):\n pass\ntry:\n pass\nexcept BaseException:\n raise SystemExit(1)',
] + ['def main():\n try:\n  pass\n except BaseException:\n  ' + body
     for body in ['pass', 'return 0', 'raise', 'raise SystemExit(0)', 'raise SystemExit(256)',
                  'raise SystemExit(1) from sys.exit(0)', 'if False:\n   raise SystemExit(1)']]
  + ['try:\n raise ' + exception + '\nexcept BaseException:\n raise SystemExit(1)'
     for exception in ['RuntimeError("synthetic")', 'BaseException()', 'SystemExit(0)']])
def test_all_runner_broad_handlers_are_refused_without_ct_extension(path, source):
    assert 5 in {r for r, _ in lint(source, path)}


@pytest.mark.parametrize('source', [
    'import re\nASCII = 0\nx = re.compile("abc", ASCII)',
    'import re\nPATTERN = "(a+)+"\nx = re.compile(PATTERN, re.ASCII)',
    'from re import ASCII\nimport re\nASCII = 0\nx = re.compile("abc", ASCII)',
    'import re\nx = re.compile("abc", re.ASCII * 0)',
])
def test_regex_flag_and_nonliteral_pattern_bypasses_are_refused(source):
    assert 12 in {r for r, _ in lint(source, 'atlas_brain/packs/example/parser.py')}


def test_parsekit_compiler_extension_is_exact_source_and_path_bound():
    path = 'atlas_brain/evidence/parsekit/patterns.py'
    source = Path(path).read_text(encoding='utf-8')
    assert not lint(source, path)
    changed = source.replace('raise ValueError("nested repeat")', 'pass')
    assert changed != source
    assert 12 in {r for r, _ in lint(changed, path)}
    assert 12 in {r for r, _ in lint(source, 'atlas_brain/packs/example/parser.py')}


@pytest.mark.parametrize("replacement", [
    ('def compile_pattern(', 'def other_compiler('),
    ('re.ASCII)', '0)'),
    ('raise ValueError("every repeat must be explicitly possessive")', 'pass'),
    ('raise ValueError("express alternatives as separate ordered rules")', 'pass'),
])
def test_compiler_extension_refuses_modified_policy(replacement):
    path = 'atlas_brain/evidence/parsekit/patterns.py'
    source = Path(path).read_text(encoding='utf-8')
    changed = source.replace(*replacement)
    assert changed != source
    assert 12 in {r for r, _ in lint(changed, path)}


def test_same_dynamic_compiler_call_elsewhere_is_refused():
    source = 'import re\ndef compile_pattern(pattern):\n return re.compile(pattern.encode("ascii"), re.ASCII)'
    for path in ('atlas_brain/evidence/parsekit/patterns.py',
                 'atlas_brain/evidence/parsekit/other.py',
                 'atlas_brain/packs/example/parser.py'):
        assert 12 in {r for r, _ in lint(source, path)}


@pytest.mark.parametrize('path,rule,source', [
    ('atlas_brain/evidence/intake.py', 9, source) for source in [
        'import os\nx = os.environ["X"]', 'from os import environ as env\nx = env["X"]',
    ]
] + [('atlas_brain/evidence/admission.py', 10, source) for source in [
    'with path.open("r") as f:\n text = f.read()',
    'import io\nwith io.open("rb", "r") as f:\n text = f.read()',
    'import builtins\nwith builtins.open("rb") as f:\n text = f.read()',
    'from pathlib import Path\nwith Path.open(path, "r") as f:\n text = f.read()',
    'text = path.read_text(None, "b")',
]])
def test_environment_and_text_read_refusals(path, rule, source):
    assert rule in {r for r, _ in lint(source, path)}
