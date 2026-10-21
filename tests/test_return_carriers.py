"""Known scoped capabilities cannot disappear inside dict or generator values."""
import subprocess
import sys
import json
import os
from pathlib import Path

import pytest

from tools.fence import source_allowed

USING = "atlas_brain/evidence/archives.py"
CARRIERS = [("return {'cap': CAP}['cap']", "factory()"),
            ("return {key: CAP for key in ('cap',)}['cap']", "factory()"),
            ("return {CAP: 'data'}", "next(iter(factory()))"),
            ("yield CAP", "next(factory())"),
            ("yield from (CAP,)", "next(factory())"),
            ("return (CAP for _ in (0,))", "next(factory())"),
            ("yield from iter((CAP,))", "next(factory())"),
            ("return iter((CAP,))", "next(factory())"),
            ("it = iter\n yield from it((CAP,))", "next(factory())"),
            ("return next(iter((CAP,)))", "factory()"),
            ("return dict(cap=CAP)['cap']", "factory()"),
            ("return {'cap': CAP}.get('cap')", "factory()"),
            ("box = {'cap': CAP}\n return box.get('cap')", "factory()"),
            ("return cast(object, CAP)", "factory()"),
            ("return map(lambda item: item, (CAP,))", "next(factory())"),
            ("return filter(None, (CAP,))", "next(factory())"),
            ("return passthrough((CAP,))", "next(factory())"),
            ("carrier = iter\n if flag:\n  carrier = lambda values: values\n return carrier((CAP,))", "next(factory(False))"),
            ("carrier = iter if flag else iter\n if flag:\n  carrier = len\n return carrier((CAP,))", "next(factory(False))"),
            ("return [CAP for _ in (0,)][0]", "factory()")]


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("body, receiver", CARRIERS)
def test_actual_cli_data_positive_then_carried_capability_refusal(tmp_path: Path, capability, body, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\nfrom typing import cast\ndef passthrough(values): return values\ndef factory(flag=False):\n " + body.replace("CAP", capability)
                     + "\ndef public_data(): return {'count': 1}\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text(
        "from .evidence.archives import factory, public_data\n", encoding="utf-8")
    probe = tmp_path / "atlas_brain/probe.py"
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import factory, public_data\n"
        probe.write_text(prefix + "factory()\npublic_data()['count']\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + receiver + f"({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("body, receiver", [
    ("return {'ok': isinstance(value, ZipFile)}['ok']", "factory(value)"),
    ("yield isinstance(value, ZipFile)", "next(factory(value))"),
    ("return type(value) is ZipFile", "factory(value)"),
    ("box = {'ok': isinstance(value, ZipFile)}\n return box.get('ok')", "factory(value)"),
    ("it = iter\n return next(it((isinstance(value, ZipFile),)))", "factory(value)"),
    ("return (1 for _ in (0,) if isinstance(value, ZipFile))", "next(factory(value))")])
def test_ordinary_predicate_and_generator_data_remain_public(body, receiver):
    sources = {USING: "from zipfile import ZipFile\ndef factory(value):\n " + body}
    assert source_allowed("from .evidence.archives import factory\n" + receiver + ".bit_length()", sources)


def test_ordinary_record_construction_keeps_its_fields():
    sources = {"atlas_brain/records.py": "from pathlib import Path\nclass Record:\n def __init__(self, path): self.name = 'record'\ndef factory(): return Record(Path('x'))"}
    assert source_allowed("from .records import factory\nfactory().name.upper()", sources)


def test_possible_primitive_predicate_aliases_remain_primitive():
    sources = {USING: "from zipfile import ZipFile\ndef factory(value, flag):\n predicate = isinstance\n if flag: predicate = issubclass\n return predicate(value, ZipFile)"}
    assert source_allowed("from .evidence.archives import factory\nfactory(value, flag).bit_length()", sources)


@pytest.mark.parametrize("kind", ["outside", "noncontract"])
@pytest.mark.parametrize("carrier", ["map(lambda item: item, (ZipFile,))", "filter(None, (ZipFile,))"])
def test_unproved_carrier_output_negative_creates_no_payload(tmp_path: Path, kind, carrier):
    package = tmp_path / "atlas_brain"
    (package / "evidence").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "evidence/archives.py").write_text(
        "from zipfile import ZipFile\ndef factory(): return " + carrier + "\n", encoding="utf-8")
    probe = package / "zz_consumer.py"
    prefix = "from .evidence.archives import factory\n"
    probe.write_text(prefix + "factory()\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    def fence():
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        return subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    root = tmp_path / "contract"
    witness = str(Path("tools/output_witness.py").resolve())
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"}
    assert fence().returncode == 0
    assert subprocess.run([sys.executable, witness, "--root", str(root)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, check=False).returncode == 0
    target = tmp_path / "forbidden.zip" if kind == "outside" else root / "notes.zip"
    probe.write_text(prefix + "next(factory())(" + repr(str(target)) + ", 'w')\n", encoding="utf-8")
    assert fence().returncode == 1
    result = subprocess.run([sys.executable, witness, "--root", str(root)], cwd=tmp_path, env=env,
                            capture_output=True, text=True, check=False)
    receipt = json.loads(result.stdout)
    assert result.returncode == 1 and receipt["completed"] is False and "open" in receipt["violations"]
    assert not target.exists()
