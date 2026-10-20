import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("probe,expected", [("engine", 0), ("inside", 0), ("outside", 1), ("rename", 1)])
def test_output_witness(tmp_path, probe, expected):
    root = tmp_path / "contract"
    result = subprocess.run(
        [sys.executable, "-m", "tools.output_witness", "--root", str(root), "--probe", probe],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, check=False,
    )
    assert result.returncode == expected, result.stderr
    assert not (tmp_path / "forbidden").exists()
    if probe == "inside":
        assert (root / "receipt.json").read_text(encoding="utf-8") == "{}"


def test_namespace_module_write_is_exercised_and_refused(tmp_path):
    package = tmp_path / "atlas_brain"
    for name, text in {"__init__.py": "", "safe.py": "", "namespace/probe.py":
                       "from pathlib import Path\nPath(" + repr(str(tmp_path / "forbidden")) + ").write_text('x', encoding='utf-8')"}.items():
        file = package / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
    tool = str(Path("tools/output_witness.py").resolve())
    result = subprocess.run([sys.executable, tool, "--root", str(tmp_path / "contract")], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, check=False)
    assert result.returncode == 1, result.stderr
    assert not (tmp_path / "forbidden").exists()
