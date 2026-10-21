"""ZIP primitives are exact per-file grants, never a runtime-module import ban."""
import re
import stat
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

USING = "atlas_brain/evidence/archives.py"
APIS = {"zipfile.ZipFile", "zipfile.BadZipFile", "zipfile.ZIP_STORED", "zipfile.ZIP_DEFLATED",
        "zlib.error", "zlib.decompressobj", "stat.S_IFMT"}


def test_zip_amendment_and_existing_bounds_are_exact():
    assert RUNTIME_API[USING] == APIS and USING not in SCOPED_API
    assert len(STDLIB_API) == 22 and not APIS & STDLIB_API
    assert len(SCOPED_API["atlas_brain/kernel/token_lints.py"]) == 29
    assert len(SCOPED_API["atlas_brain/kernel/lints.py"]) == 32
    text = Path("docs/adr/0009-adr0002-zip-runtime.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| ([\w.]+) \|", text)) == APIS
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


@pytest.mark.parametrize("api", sorted(APIS))
def test_exact_zip_using_file_and_outside_refusal(api):
    module, name = api.rsplit(".", 1)
    source = f"from {module} import {name} as value; value"
    assert source_allowed(source, path=USING)
    for path in ("atlas_brain/packs/example.py", "atlas_brain/evidence/archive.py", USING + "/extra.py"):
        assert not source_allowed(source, path=path)


@pytest.mark.parametrize("module", [zipfile, zlib, stat])
def test_all_actual_unlisted_zip_namespace_names_refuse(module):
    for name in sorted(vars(module)):
        api = module.__name__ + "." + name
        if name.isidentifier() and api not in APIS | STDLIB_API:
            assert not source_allowed(f"from {module.__name__} import {name}", path=USING), api
    assert not source_allowed("from zipfile import *", path=USING)
    assert not source_allowed("import ast; ast.parse('')", path=USING)
    assert not source_allowed("import subprocess", path=USING)


@pytest.mark.parametrize("api", sorted(APIS))
def test_zip_capability_reexports_refuse_without_blocking_public_declarations(api):
    module, name = api.rsplit(".", 1)
    sources = {USING: f"from {module} import {name} as leaked\ndef zip_members(path): return path",
               "atlas_brain/bridge.py": "from .evidence.archives import leaked"}
    assert source_allowed("from .evidence.archives import zip_members; zip_members(path)", sources)
    assert not source_allowed("from .evidence.archives import leaked; leaked", sources)
    assert not source_allowed("from .evidence import archives; archives.leaked", sources)
    assert not source_allowed("from .bridge import leaked; leaked", sources)


@pytest.mark.parametrize("api", sorted(APIS))
def test_real_tracked_cli_uses_exact_zip_file_scope(tmp_path: Path, api):
    module, name = api.rsplit(".", 1)
    source = f"from {module} import {name}; {name}\n"
    file = tmp_path / USING
    file.parent.mkdir(parents=True)
    file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    (tmp_path / "atlas_brain/probe.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 1 and "scope fence: 1 refused" in result.stdout
    assert api in result.stdout and "atlas_brain/probe.py" in result.stdout
