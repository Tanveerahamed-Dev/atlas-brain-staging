import os
import subprocess
import sys

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
