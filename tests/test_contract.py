"""Planted contract violations; acceptance runs on the pinned hosted interpreter."""
from dataclasses import dataclass
from typing import Literal

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from tools.contract_lint import violations
from tools.contract_schema import schema_for, verify_revision


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf"),
    {"nested": [0.5]}, 9007199254740992, -9007199254740992,
    "\ud800", {"\udfff": 1}, {1: "bad"}, {"x": object()}, {1, 2}])
def test_writer_refuses_planted_values(value):
    with pytest.raises((ValueError, TypeError, UnicodeError)):
        canonical(value)


def test_rfc8785_utf16_key_order_and_escapes():
    value = {"\ue000": 3, "\U0001f600": 2, "\r": "\b\t\n\f\r\x00\x1f\"\\/"}
    assert canonical(value) == ('{"\\r":"\\b\\t\\n\\f\\r\\u0000\\u001f\\\"\\\\/",'
        '"\U0001f600":2,"\ue000":3}').encode()
    assert canonical({"b": [True, None, False], "a": -9007199254740991}) == (
        b'{"a":-9007199254740991,"b":[true,null,false]}')
    assert canonical(9007199254740991) == b"9007199254740991"
    assert canonical("e\u0301") != canonical("\u00e9")


def test_manifest_known_hash_and_sorted_posix_paths():
    files = {"result.json": b"{}", "facts/node.jsonl": b""}
    assert manifest(files) == (
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  facts/node.jsonl\n"
        b"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  result.json\n")
    assert manifest(dict(reversed(list(files.items())))) == manifest(files)


@pytest.mark.parametrize("name", ["../x.json", "/x.json", "facts//x.jsonl",
    "facts\\x.jsonl", "facts/../x.jsonl", "result.json\nother", "MANIFEST.sha256",
    "Facts/node.jsonl", "receipt.json", "facts/x.jsonl\x00"])
def test_manifest_refuses_unsafe_or_noncontract_names(name):
    with pytest.raises(ValueError):
        manifest({"result.json": b"{}", name: b""})
    with pytest.raises(ValueError):
        manifest({"facts/node.jsonl": b""})


@pytest.mark.parametrize("plant", ["x = a + b", "x += 1", "x = a * b",
    "x = -a", "x = a < b", "x = a == b", "x = sum(rows)",
    "x = min(rows)", "x = statistics.mean(rows)", "from operator import add",
    "import math", "f = sum", "from builtins import sum as fold",
    "x: a + b", "x: tuple[sum(rows)]", "type X = a + b", "x = ~a",
    "x = value.__add__(other)", "x = eval(source)", "x = ~1"])
def test_contract_lint_fires_on_each_planted_computation(plant):
    assert violations(plant)


def test_contract_tree_and_declarative_types_pass_lint():
    from pathlib import Path
    for path in Path("atlas_brain/contract").rglob("*.py"):
        assert not violations(path.read_text(encoding="utf-8")), path
    assert not violations("x: str | int\nLIMIT = -9007199254740991")


@dataclass(frozen=True, slots=True)
class Sample:
    schema_version: Literal["0.1.0"]
    counter: int
    labels: tuple[str, ...]


def test_schema_is_202012_generated_and_integer_bounded():
    schema = schema_for(Sample, "0.1.0")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    root = schema["$defs"]["Sample"]
    assert root["required"] == ["schema_version", "counter", "labels"]
    assert root["additionalProperties"] is False
    assert root["properties"]["counter"] == {
        "type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
    assert root["properties"]["labels"] == {"type": "array", "items": {"type": "string"}}
    verify_revision(schema, schema)
    changed = schema_for(Sample, "0.1.0")
    changed["$defs"]["Sample"]["properties"]["extra"] = {"type": "string"}
    with pytest.raises(ValueError, match="schema_version"):
        verify_revision(schema, changed)
    changed["x-schema-version"] = "0.2.0"
    verify_revision(schema, changed)


@pytest.mark.parametrize("annotation", [float, set[str], object, tuple[int, str]])
def test_schema_fails_closed_on_unsupported_types(annotation):
    with pytest.raises(TypeError):
        schema_for(annotation, "0.1.0")


def test_planted_arithmetic_fails_real_lint_entrypoint(tmp_path):
    import subprocess
    import sys
    plant = tmp_path / "projection.py"
    plant.write_text("result = left + right", encoding="utf-8")
    result = subprocess.run([sys.executable, "tools/contract_lint.py", str(plant)],
        capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "computation refused" in result.stdout
