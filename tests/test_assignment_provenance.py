"""Assignments preserve import provenance; opaque protected roots fail closed."""
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import STDLIB_API, ImportIndex, source_allowed

USING = "atlas_brain/evidence/producer.py"
MODULE = "atlas_brain.evidence.producer."
SHAPES = {
    "plain": "leaked = capability",
    "chain": "first = capability\nleaked = first",
    "annotated": "leaked: object = capability",
    "tuple": "leaked, other = capability, 0",
    "module": "import zipfile\nleaked = zipfile.ZipFile",
    "conditional": "leaked = capability if flag else capability",
    "class": "class Holder:\n    leaked = capability",
    "boolean": "leaked = capability or capability",
    "named": "leaked = (other := capability)",
    "container": "leaked = (capability,)[0]",
}


@pytest.mark.parametrize("shape", SHAPES)
def test_assignment_origin_is_canonical_or_refused_through_bridge(shape):
    symbol = "Holder.leaked" if shape == "class" else "leaked"
    sources = {USING: "from zipfile import ZipFile as capability\n" + SHAPES[shape],
               "atlas_brain/bridge.py": "from .evidence import producer\nexported = producer." + symbol}
    index = ImportIndex(sources)
    expected = None if shape == "container" else "zipfile.ZipFile"
    assert index.origin(MODULE + symbol) == expected
    assert index.origin("atlas_brain.bridge.exported") == expected
    assert not source_allowed("from .evidence import producer; producer." + symbol, sources)
    assert not source_allowed("from .bridge import exported; exported", sources)


@pytest.mark.parametrize("assignment", [
    "leaked = capability if flag else 0", "leaked = capability or 0",
    "leaked = 0\nleaked = capability", "leaked = capability\nleaked = 0",
    "leaked = [capability][0]", "leaked = {'api': capability}['api']",
    "leaked = (capability,)[0]\nleaked = leaked()",
    "leaked = unknown(capability)", "leaked, *rest = unknown(capability)",
])
def test_unproven_rhs_or_rebinding_is_not_an_engine_declaration(assignment):
    sources = {USING: "from zipfile import ZipFile as capability\n" + assignment}
    assert ImportIndex(sources).origin(MODULE + "leaked") is None
    assert not source_allowed("from .evidence.producer import leaked", sources)


@pytest.mark.parametrize("body", [
    "from pathlib import Path\nvalue = Path('synthetic')",
    "import re\nvalue = re.compile('synthetic')",
    "def helper(): pass\nvalue = helper()", "class Record: pass\nvalue = Record()",
    "value = {'synthetic': 1}", "value = [1, 2][0]",
])
def test_ordinary_declarations_and_globally_admitted_data_stay_importable(body):
    sources = {USING: body + "\ndef public(value): return value\nclass PublicRecord: pass"}
    assert ImportIndex(sources).origin(MODULE + "value") == MODULE + "value"
    assert source_allowed("from .evidence.producer import value, public, PublicRecord", sources)
    assert len(STDLIB_API) == 22


@pytest.mark.parametrize("rhs", ["Path", "Path or Path", "(Path,)[0]", "Path('synthetic')"])
def test_actual_cli_keeps_globally_admitted_producers_and_public_declarations(tmp_path: Path, rhs):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from pathlib import Path\nvalue = " + rhs + "\ndef public(value): return value\nclass Record: pass\n", encoding="utf-8")
    (tmp_path / "atlas_brain/probe.py").write_text("from .evidence.producer import value, public, Record\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0 and "scope fence: 0 refused" in result.stdout
