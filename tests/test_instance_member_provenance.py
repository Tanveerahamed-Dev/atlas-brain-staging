"""Public data imports retain factory provenance at member-access boundaries."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import STDLIB_API, ImportIndex, source_allowed

USING = "atlas_brain/evidence/producer.py"
MODULE = "atlas_brain.evidence.producer.value"
PRODUCERS = [
    "from pathlib import Path\nvalue = Path('synthetic')",
    "from pathlib import Path\nfirst = Path('synthetic')\nvalue = first",
    "import pathlib\nvalue = pathlib.Path('synthetic')",
    "from pathlib import Path\nvalue = Path('a') if flag else Path('b')",
    "from pathlib import Path\nvalue = (Path('synthetic'),)[0]",
]
RECEIVERS = ["value", "(value if True else value)", "(value / 'child')",
             "([value][0])", "(value or value)", "(alias := value)", "(lambda: value)()",
             "borrowed", "(borrowed if True else borrowed)"]


@pytest.mark.parametrize("producer", PRODUCERS)
@pytest.mark.parametrize("member", ["write_text", "write_bytes", "open", "unlink"])
def test_public_instance_data_does_not_turn_members_into_engine_declarations(producer, member):
    sources = {USING: producer, "atlas_brain/bridge.py": "from .evidence.producer import value\nexported = value"}
    index = ImportIndex(sources)
    assert index.origin(MODULE) == MODULE
    assert index.origin(MODULE + "." + member) == "pathlib.Path." + member
    assert index.origin("atlas_brain.bridge.exported." + member) == "pathlib.Path." + member
    assert source_allowed("from .evidence.producer import value\nvalue", sources)
    assert not source_allowed("from .evidence.producer import value\nvalue." + member, sources)
    assert not source_allowed("from .bridge import exported\nexported." + member, sources)
    assert "pathlib.Path." + member not in STDLIB_API


@pytest.mark.parametrize("body", [
    "value = Path('synthetic').write_text",
    "first = Path('synthetic')\nvalue = first.write_text",
    "value = (Path('synthetic').write_text,)[0]",
])
def test_bound_member_aliases_do_not_drop_the_member_suffix(body):
    sources = {USING: "from pathlib import Path\n" + body,
               "atlas_brain/bridge.py": "from .evidence.producer import value\nexported = value"}
    assert ImportIndex(sources).origin(MODULE) is None
    assert not source_allowed("from .evidence.producer import value\nvalue('x')", sources)
    assert not source_allowed("from .bridge import exported\nexported('x')", sources)


def test_factory_arguments_keep_protected_roots_and_engine_data_keeps_public_fields():
    protected = {USING: "from typing import cast\nfrom zipfile import ZipFile\nvalue = cast(object, ZipFile)"}
    assert ImportIndex(protected).origin(MODULE) is None
    assert not source_allowed("from .evidence.producer import value", protected)
    ordinary = {"atlas_brain/records.py": "class Record: pass",
                USING: "from ..records import Record\nvalue = Record()"}
    assert source_allowed("from .evidence.producer import value\nvalue.field", ordinary)


@pytest.mark.parametrize("receiver", RECEIVERS)
def test_expression_receiver_cannot_hide_a_known_imported_capability(receiver):
    sources = {USING: PRODUCERS[0]}
    assert source_allowed("from .evidence.producer import value\nvalue", sources)
    assert not source_allowed("from .evidence.producer import value\nborrowed = value\n" + receiver + ".write_text('x')", sources)
    ordinary = {USING: "class Record: pass\nvalue = Record()"}
    assert source_allowed("from .evidence.producer import value\n(value if True else value).field", ordinary)


def tracked_cli(root):
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    return subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())], cwd=root,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("producer", PRODUCERS[:3])
@pytest.mark.parametrize("receiver", RECEIVERS)
def test_actual_two_file_cli_allows_data_but_refuses_direct_and_bridge_writes(tmp_path: Path, producer, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(producer + "\ndef public(value): return value\nclass Record: pass\n", encoding="utf-8")
    consumer = tmp_path / "atlas_brain/probe.py"
    consumer.write_text("from .evidence.producer import value, public, Record\nvalue\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert tracked_cli(tmp_path).returncode == 0
    consumer.write_text("from .evidence.producer import value\nborrowed = value\n" + receiver + ".write_text('x')\n", encoding="utf-8")
    direct = tracked_cli(tmp_path)
    assert direct.returncode == 1 and "atlas_brain/probe.py" in direct.stdout
    assert "pathlib.Path.write_text" not in STDLIB_API
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.producer import value\nexported = value\n", encoding="utf-8")
    consumer.write_text("from .bridge import exported as value\nborrowed = value\n" + receiver + ".write_text('x')\n", encoding="utf-8")
    bridge = tracked_cli(tmp_path)
    assert bridge.returncode == 1 and "atlas_brain/probe.py" in bridge.stdout


def test_actual_cli_tracks_function_local_data_alias_receivers(tmp_path: Path):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(PRODUCERS[0], encoding="utf-8")
    (tmp_path / "atlas_brain/probe.py").write_text(
        "from .evidence.producer import value\ndef write():\n borrowed = value\n (borrowed if True else borrowed).write_text('x')\nwrite()\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    result = tracked_cli(tmp_path)
    assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("kind", ["outside", "noncontract"])
@pytest.mark.parametrize("receiver", RECEIVERS[:3])
def test_two_file_output_path_negative_is_refused_without_creating_payload(tmp_path: Path, kind, receiver):
    package = tmp_path / "atlas_brain"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    root = tmp_path / "contract"
    target = tmp_path / "forbidden" if kind == "outside" else root / "notes.txt"
    (package / "aa_producer.py").write_text("from pathlib import Path\nvalue = Path(" + repr(str(target)) + ")\n", encoding="utf-8")
    consumer = package / "zz_consumer.py"
    consumer.write_text("from .aa_producer import value\nvalue\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert tracked_cli(tmp_path).returncode == 0
    tool = str(Path("tools/output_witness.py").resolve())
    def witness():
        return subprocess.run([sys.executable, tool, "--root", str(root)], cwd=tmp_path,
                              env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                              capture_output=True, text=True, check=False)
    assert witness().returncode == 0
    consumer.write_text("from .aa_producer import value\n" + receiver + ".write_text('x', encoding='utf-8')\n", encoding="utf-8")
    assert tracked_cli(tmp_path).returncode == 1
    result = witness()
    receipt = json.loads(result.stdout)
    assert result.returncode == 1 and receipt["completed"] is False and "open" in receipt["violations"]
    assert not target.exists()
