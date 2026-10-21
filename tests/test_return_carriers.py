"""Known scoped capabilities cannot disappear inside dict or generator values."""
import subprocess
import sys
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
            ("return [CAP for _ in (0,)][0]", "factory()")]


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("body, receiver", CARRIERS)
def test_actual_cli_data_positive_then_carried_capability_refusal(tmp_path: Path, capability, body, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\nfrom typing import cast\ndef factory():\n " + body.replace("CAP", capability)
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
